/**
 * PQC Manager
 * Manages ML-DSA-87 Keys in WebAssembly, WebAuthn PRF, and Argon2 recovery.
 */

class PqcManager {
    constructor() {
        this.module = null;
        this.skPtr = null; // Pointer to Secret Key in WASM memory
        this.pk = null; // Uint8Array of Public Key
        this.activeKeyId = null;
        this.isUnlocked = false;
        
        // Constants for ML-DSA-87
        this.PK_LEN = 2592;
        this.SK_LEN = 4896;
        this.SIG_LEN = 4627;
        
        this.lockTimeout = null;
        this.LOCK_MINUTES = 30; // Auto-lock after 30 minutes of inactivity
        
        this.initPromise = this._initWasm();
        this._setupActivityListeners();
    }

    async _initWasm() {
        if (typeof liboqs === 'function') {
            this.module = await liboqs();
        } else {
            console.error("liboqs is not loaded.");
        }
    }

    _setupActivityListeners() {
        // Reset the timeout on any user interaction if unlocked
        const resetTimer = () => {
            if (this.isUnlocked) {
                this._resetLockTimeout();
            }
        };
        
        document.addEventListener('mousemove', resetTimer);
        document.addEventListener('keydown', resetTimer);
        document.addEventListener('click', resetTimer);
        document.addEventListener('scroll', resetTimer);
        window.addEventListener('pagehide', () => this.lock());
    }

    _resetLockTimeout() {
        if (this.lockTimeout) {
            clearTimeout(this.lockTimeout);
        }
        this.lockTimeout = setTimeout(() => {
            this.lock();
            // Show a notification to the user that session expired
            alert("PQC Signature Session auto-locked due to 30 minutes of inactivity. You will need to use your Passkey again.");
        }, this.LOCK_MINUTES * 60 * 1000);
    }

    /**
     * Clear and release the WASM buffer that holds the signing key.
     */
    lock() {
        if (this.skPtr !== null && this.module !== null) {
            this.module.HEAPU8.fill(0, this.skPtr, this.skPtr + this.SK_LEN);
            this.module._free(this.skPtr);
            this.skPtr = null;
        }
        this.pk = null;
        this.activeKeyId = null;
        this.isUnlocked = false;
        
        if (this.lockTimeout) {
            clearTimeout(this.lockTimeout);
            this.lockTimeout = null;
        }
        console.log("PQC Manager: Secret Key wiped from WASM memory.");
    }

    /**
     * Verify the selected passkey can reproduce its PRF output during unlock.
     */
    async _getPrfKey(isCreate = false, serverCredId = null) {
        const username = localStorage.getItem('username') || 'unknown_user';
        const salt = new Uint8Array(sha3_256.arrayBuffer(`Cloud-Policy-PRF-Salt-${username}`));
        const extensions = { prf: { eval: { first: salt } } };
        const rpId = window.location.hostname;
        if (!window.PublicKeyCredential || !navigator.credentials) {
            throw new DOMException("WebAuthn is unavailable in this browser session.", 'NotSupportedError');
        }

        let credentialId = serverCredId;
        if (isCreate) {
            const credential = await navigator.credentials.create({
                publicKey: {
                    challenge: crypto.getRandomValues(new Uint8Array(32)),
                    rp: { name: "Cloud Policy Crypto Access", id: rpId },
                    user: {
                        id: crypto.getRandomValues(new Uint8Array(16)),
                        name: `${username} (Signature)`,
                        displayName: `${username} (Signature)`
                    },
                    pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
                    authenticatorSelection: { userVerification: "required", residentKey: "required" },
                    extensions
                }
            });
            if (!credential) throw new DOMException("Passkey creation was cancelled.", 'NotAllowedError');
            if (credential.getClientExtensionResults().prf?.enabled === false) {
                throw new DOMException("Your provider saved the passkey but reported that PRF is disabled for it.", 'NotSupportedError');
            }
            credentialId = btoa(String.fromCharCode(...new Uint8Array(credential.rawId)));
        } else {
            credentialId ||= localStorage.getItem('pqc_credential_id');
        }

        const publicKey = {
            challenge: crypto.getRandomValues(new Uint8Array(32)),
            rpId,
            userVerification: 'required',
            extensions
        };
        if (credentialId) {
            publicKey.allowCredentials = [{
                id: Uint8Array.from(atob(credentialId), c => c.charCodeAt(0)),
                type: 'public-key'
            }];
        }
        const credential = await navigator.credentials.get({ publicKey });
        if (!credential) throw new DOMException("Passkey verification was cancelled.", 'NotAllowedError');
        const returnedId = btoa(String.fromCharCode(...new Uint8Array(credential.rawId)));
        if (credentialId && returnedId !== credentialId) {
            throw new Error("The browser returned a different signing passkey.");
        }
        const prfOutput = credential.getClientExtensionResults().prf?.results?.first;
        if (prfOutput?.byteLength !== 32) {
            throw new DOMException("The browser returned the passkey, but it did not return the 32-byte PRF result needed to unlock your signing key.", 'NotSupportedError');
        }
        const prfBytes = ArrayBuffer.isView(prfOutput)
            ? new Uint8Array(prfOutput.buffer, prfOutput.byteOffset, prfOutput.byteLength)
            : new Uint8Array(prfOutput);
        try {
            const key = await crypto.subtle.importKey("raw", prfBytes, "AES-GCM", false, ["encrypt", "decrypt"]);
            return { key, credentialId: returnedId };
        } finally {
            prfBytes.fill(0);
        }
    }

    /**
     * Derive a 256-bit symmetric key from a 24-word Mnemonic using Argon2.
     */
    async _getArgon2Key(mnemonicWords, salt, version) {
        const pass = new TextEncoder().encode(mnemonicWords.join(' '));
        let hash;
        try {
            ({ hash } = await argon2.hash({
                pass, salt, time: 3, mem: 65536, hashLen: 32,
                parallelism: version === 2 ? 4 : 1,
                // The bundled library defaulted old unversioned records to Argon2d.
                type: version === 2 ? argon2.ArgonType.Argon2id : argon2.ArgonType.Argon2d
            }));
            return await crypto.subtle.importKey("raw", hash, "AES-GCM", false, ["encrypt", "decrypt"]);
        } finally {
            pass.fill(0);
            hash?.fill(0);
        }
    }

    async _wrapRecoveryKey(mnemonic, readSecret) {
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const key = await this._getArgon2Key(mnemonic, salt, 2);
        const encrypted = await this._encryptKey(key, readSecret());
        return `v2:${btoa(String.fromCharCode(...salt))}:${encrypted}`;
    }

    async _unwrapRecoveryKey(mnemonic, value) {
        if (typeof value !== 'string' || !value) throw new Error("Recovery data is unavailable.");
        if (!value.includes(':')) {
            const username = localStorage.getItem('username') || 'unknown_user';
            const salt = new TextEncoder().encode(`Cloud-Policy-Salt-${username}`);
            const key = await this._getArgon2Key(mnemonic, salt, 1);
            return this._decryptKey(key, value);
        }
        const [version, saltText, ciphertext, ...extra] = value.split(':');
        if (version !== 'v2' || !saltText || !ciphertext || extra.length) {
            throw new Error("Unsupported recovery key format.");
        }
        const salt = Uint8Array.from(atob(saltText), c => c.charCodeAt(0));
        if (salt.length !== 16) throw new Error("Invalid recovery salt.");
        const key = await this._getArgon2Key(mnemonic, salt, 2);
        return this._decryptKey(key, ciphertext);
    }

    /**
     * Generate 24 independent words with a cryptographic RNG.
     */
    _generateMnemonic() {
        const words = ["abandon","ability","able","about","above","absent","absorb","abstract","absurd","abuse","access","accident","account","accuse","achieve","acid","acoustic","acquire","across","act","action","actor","actress","actual","adapt","add","addict","address","adjust","admit","adult","advance","advice","aerobic","affair","afford","afraid","again","age","agent","agree","ahead","aim","air","airport","aisle","alarm","album","alcohol","alert","alien","all","alley","allow","almost","alone","alpha","already","also","alter","always","amateur","amazing","among","amount","amused","analyst","anchor","ancient","anger","angle","angry","animal","ankle","announce","annual","another","answer","antenna","antique","anxiety","any","apart","apology","appear","apple","approve","april","arch","arctic","area","arena","argue","arm","armed","armor","army","around","arrange","arrest","arrive","arrow","art","artefact","artist","artwork","ask","aspect","assault","asset","assist","assume","asthma","athlete","atom","attack","attend","attitude","attract","auction","audit","august","aunt","author","auto","autumn","average","avocado","avoid","awake","aware","away","awesome","awful","awkward","axis","baby","bachelor","bacon","badge","bag","balance","balcony","ball","bamboo","banana","banner","bar","barely","bargain","barrel","base","basic","basket","battle","beach","bean","beauty","because","become","beef","before","begin","behave","behind","believe","below","belt","bench","benefit","best","betray","better","between","beyond","bicycle","bid","bike","bind","biology","bird","birth","bitter","black","blade","blame","blanket","blast","bleak","blind","blood","blossom","blouse","blue","blur","board","boat","body","boil","bomb","bone","bonus","book","boost","border","boring","borrow","boss","bottom","bounce","box","boy","bracket","brain","brand","brass","brave","bread","breeze","brick","bridge","brief","bright","bring","brisk","broccoli","broken","bronze","broom","brother","brown","brush","bubble","buddy","budget","buffalo","build","bulb","bulk","bullet","bundle","burden","burger","burst","bus","business","busy","butter","buyer","buzz","cabbage","cabin","cable","cactus","cage","cake","call","calm","camera","camp","can","canal","cancel","candy","cannon","canoe","canvas","canyon","capable","capital","captain","car","carbon","card","cargo","carpet","carry","cart","case","cash","casino","castle","casual","cat","catalog","catch","category","cattle","caught","cause","caution","cave","ceiling","celery","cement","census","century","cereal","certain","chair","chalk","champion","change","chaos","chapter","charge","chase","chat","cheap","check","cheese","chef","cherry","chest","chicken","chief","child","chimney","choice","choose","chronic","chuckle","chunk","churn","cigar","cinnamon","circle","citizen","city","civil","claim","clap","clarify","claw","clay","clean","clerk","clever","click","client","cliff","climb","clinic","clip","clock","clog","close","cloth","cloud","clown","club","clump","cluster","clutch","coach","coast","coconut","code","coffee","coil","coin","collect","color","column","combine","come","comfort","comic","common","company","concert","conduct","confirm","congress","connect","consider","control","convince","cook","cool","copper","copy","coral","core","corn","correct","cost","cotton","couch","country","couple","course","cousin","cover","coyote","crack","cradle","craft","cram","crane","crash","crater","crawl","crazy","cream","credit","creek","crew","cricket","crime","crisp","critic","crop","cross","crowd","crucial","cruel","cruise","crumble","crunch","crush","cry","crystal","cube","culture","cup","cupboard","curious","current","curtain","curve","cushion","custom","cute","cycle","dad","damage","damp","dance","danger","daring","dash","daughter","dawn","day","deal","debate","debris","decade","december","decide","decline","decorate","decrease","deer","defense","define","defy","degree","delay","deliver","demand","demise","denial","dentist","deny","depart","depend","deposit","depth","deputy","derive","describe","desert","design","desk","despair","destroy","detail","detect","develop","device","devote","diagram","dial","diamond","diary","dice","diesel","diet","differ","digital","dignity","dilemma","dinner","dinosaur","direct","dirt","disagree","discover","disease","dish","dismiss","disorder","display","distance","divert","divide","divorce","dizzy","doctor","document","dog","doll","dolphin","domain","donate","donkey","donor","door","dose","double","dove","draft","dragon","drama","drastic","draw","dream","dress","drift","drill","drink","drip","drive","drop","drum","dry","duck","dumb","dune","during","dust","dutch","duty","dwarf","dynamic","eager","eagle","early","earn","earth","easily","east","easy","echo","ecology","economy","edge","edit","educate","effort","egg","eight","either","elbow","elder","electric","elegant","element","elephant","elevator","elite","else","embark","embody","embrace","emerge","emotion","employ","empower","empty","enable","enact","end","endless","endorse","enemy","energy","enforce","engage","engine","enhance","enjoy","enlist","enough","enrich","enroll","ensure","enter","entire","entry","envelope","episode","equal","equip","era","erase","erode","erosion","error","erupt","escape","essay","essence","estate","eternal","ethics","evidence","evil","evoke","evolve","exact","example","excess","exchange","excite","exclude","excuse","execute","exercise","exhaust","exhibit","exile","exist","exit","exotic","expand","expect","expire","explain","expose","express","extend","extra","eye","eyebrow","fabric","face","faculty","fade","faint","faith","fall","false","fame","family","famous","fan","fancy","fantasy","farm","fashion","fat","fatal","father","fatigue","fault","favorite","feature","february","federal","fee","feed","feel","female","fence","festival","fetch","fever","few","fiber","fiction","field","figure","file","film","filter","final","find","fine","finger","finish","fire","firm","first","fiscal","fish","fit","fitness","fix","flag","flame","flash","flat","flavor","flee","flight","flip","float","flock","floor","flower","fluid","flush","fly","foam","focus","fog","foil","fold","follow","food","foot","force","forest","forget","fork","fortune","forum","forward","fossil","foster","found","fox","fragile","frame","frequent","fresh","friend","fringe","frog","front","frost","frown","frozen","fruit","fuel","fun","funny","furnace","fury","future","gadget","gain","galaxy","gallery","game","gap","garage","garbage","garden","garlic","garment","gas","gasp","gate","gather","gauge","gaze","general","genius","genre","gentle","genuine","gesture","ghost","giant","gift","giggle","ginger","giraffe","girl","give","glad","glance","glare","glass","glide","glimpse","globe","gloom","glory","glove","glow","glue","goat","goddess","gold","good","goose","gorilla","gospel","gossip","govern","gown","grab","grace","grain","grant","grape","grass","gravity","great","green","grid","grief","grit","grocery","group","grow","grunt","guard","guess","guide","guilt","guitar","gun","gym","habit","hair","half","hammer","hamster","hand","happy","harbor","hard","harsh","harvest","hat","have","hawk","hazard","head","health","heart","heavy","hedgehog","height","hello","helmet","help","hen","hero","hidden","high","hill","hint","hip","hire","history","hobby","hockey","hold","hole","holiday","hollow","home","honey","hood","hope","horn","horror","horse","hospital","host","hotel","hour","hover","hub","huge","human","humble","humor","hundred","hungry","hunt","hurdle","hurry","hurt","husband","hybrid","ice","icon","idea","identify","idle","ignore","ill","illegal","illness","image","imitate","immense","immune","impact","impose","improve","impulse","inch","include","income","increase","index","indicate","indoor","industry","infant","inflict","inform","inhale","inherit","initial","inject","injury","inmate","inner","innocent","input","inquiry","insane","insect","inside","inspire","install","intact","interest","into","invest","invite","involve","iron","island","isolate","issue","item","ivory","jacket","jaguar","jar","jazz","jealous","jeans","jelly","jewel","job","join","joke","journey","joy","judge","juice","jump","jungle","junior","junk","just","kangaroo","keen","keep","ketchup","key","kick","kid","kidney","kind","kingdom","kiss","kit","kitchen","kite","kitten","kiwi","knee","knife","knock","know","lab","label","labor","ladder","lady","lake","lamp","language","laptop","large","later","latin","laugh","laundry","lava","law","lawn","lawsuit","layer","lazy","leader","leaf","learn","leave","lecture","left","leg","legal","legend","leisure","lemon","lend","length","lens","leopard","lesson","letter","level","liar","liberty","library","license","life","lift","light","like","limb","limit","link","lion","liquid","list","little","live","lizard","load","loan","logic","logo","lonely","long","look","loop","lottery","loud","lounge","love","loyal","lucky","luggage","lumber","lunar","lunch","luxury","lyrics","machine","mad","magic","magnet","maid","mail","main","major","make","mammal","man","manage","mandate","mango","mansion","manual","map","marble","march","margin","marine","market","marriage","mask","mass","master","match","material","math","matrix","matter","maximum","maze","meadow","mean","measure","meat","mechanic","medal","media","melody","melt","member","memory","mention","menu","mercy","merge","merit","merry","mesh","message","metal","method","middle","midnight","milk","million","mimic","mind","minimum","minor","minute","miracle","mirror","misery","miss","mistake","mix","mixed","mixture","mobile","model","modify","mom","moment","monitor","monkey","monster","month","moon","moral","more","morning","mosquito","mother","motion","motor","mountain","mouse","move","movie","much","muffin","mule","multiply","muscle","museum","mushroom","music","must","mutual","myself","mystery","myth","naive","name","napkin","narrow","nasty","nation","nature","near","neck","need","negative","neglect","neither","nephew","nerve","nest","net","network","neutral","never","news","next","nice","night","noble","noise","nominee","noodle","normal","north","nose","notable","note","nothing","notice","novel","now","nuclear","number","nurse","nut","oak","obey","object","oblige","obscure","observe","obtain","obvious","occur","ocean","october","odor","off","offer","office","often","oil","okay","old","olive","olympic","omit","once","one","onion","online","only","open","opera","opinion","oppose","option","orange","orbit","orchard","order","ordinary","organ","orient","original","orphan","ostrich","other","outdoor","outer","output","outside","oval","oven","over","own","owner","oxygen","oyster","ozone","pact","paddle","page","pair","palace","palm","panda","panel","panic","panther","paper","parade","parent","park","parrot","party","pass","patch","path","patient","patrol","pattern","pause","pave","payment","peace","peanut","pear","peasant","pelican","pen","penalty","pencil","people","pepper","perfect","permit","person","pet","phone","photo","phrase","physical","piano","picnic","picture","piece","pig","pigeon","pill","pilot","pink","pioneer","pipe","pistol","pitch","pizza","place","planet","plastic","plate","play","please","pledge","pluck","plug","plunge","poem","poet","point","polar","pole","police","pond","pony","pool","popular","portion","position","possible","post","potato","pottery","poverty","powder","power","practice","praise","predict","prefer","prepare","present","pretty","prevent","price","pride","primary","print","priority","prison","private","prize","problem","process","produce","profit","program","project","promote","proof","property","prosper","protect","proud","provide","public","pudding","pull","pulp","pulse","pumpkin","punch","pupil","puppy","purchase","purity","purpose","purse","push","put","puzzle","pyramid","quality","quantum","quarter","question","quick","quit","quiz","quote","rabbit","raccoon","race","rack","radar","radio","rail","rain","raise","rally","ramp","ranch","random","range","rapid","rare","rate","rather","raven","raw","razor","ready","real","reason","rebel","rebuild","recall","receive","recipe","record","recycle","reduce","reflect","reform","refuse","region","regret","regular","reject","relax","release","relief","rely","remain","remember","remind","remove","render","renew","rent","reopen","repair","repeat","replace","report","require","rescue","resemble","resist","resource","response","result","retire","retreat","return","reunion","reveal","review","reward","rhythm","rib","ribbon","rice","rich","ride","ridge","rifle","right","rigid","ring","riot","ripple","risk","ritual","rival","river","road","roast","robot","robust","rocket","romance","roof","rookie","room","rose","rotate","rough","round","route","royal","rubber","rude","rug","rule","run","runway","rural","sad","saddle","sadness","safe","sail","salad","salmon","salon","salt","salute","same","sample","sand","satisfy","satoshi","sauce","sausage","save","say","scale","scan","scare","scatter","scene","scheme","school","science","scissors","scorpion","scout","scrap","screen","script","scrub","sea","search","season","seat","second","secret","section","security","seed","seek","segment","select","sell","seminar","senior","sense","sentence","series","service","session","settle","setup","seven","shadow","shaft","shallow","share","shed","shell","sheriff","shield","shift","shine","ship","shiver","shock","shoe","shoot","shop","short","shoulder","shove","shrimp","shrug","shuffle","shy","sibling","sick","side","siege","sight","sign","silent","silk","silly","silver","similar","simple","since","sing","siren","sister","situate","six","size","skate","sketch","ski","skill","skin","skirt","skull","slab","slam","sleep","slide","slight","slip","slogan","slot","slow","slush","small","smart","smile","smoke","smooth","snack","snake","snap","sniff","snow","soap","soccer","social","sock","soda","soft","solar","soldier","solid","solution","solve","someone","song","soon","sorry","sort","soul","sound","soup","source","south","space","spare","spatial","spawn","speak","special","speed","spell","spend","sphere","spice","spider","spike","spin","spirit","split","spoil","sponsor","spoon","sport","spot","spray","spread","spring","spy","square","squeeze","squirrel","stadium","staff","stage","stairs","stamp","stand","start","state","stay","steak","steel","stem","step","stereo","stick","still","sting","stock","stomach","stone","stool","story","stove","strategy","street","strike","strong","struggle","student","stuff","stumble","style","subject","submit","subway","success","such","sudden","suffer","sugar","suggest","suit","summer","sun","sunny","sunset","super","supply","supreme","sure","surface","surge","surprise","surround","survey","suspect","sustain","swallow","swamp","swap","swarm","swear","sweet","swift","swim","swing","switch","sword","symbol","symptom","syrup","system","table","tackle","tag","tail","talent","talk","tank","tape","target","task","taste","tattoo","taxi","teach","team","tell","ten","tenant","tennis","tent","term","test","text","thank","that","theme","then","theory","there","they","thing","this","thought","three","thrive","throw","thumb","thunder","ticket","tide","tiger","tilt","timber","time","tiny","tip","tired","tissue","title","toast","tobacco","today","toddler","toe","together","toilet","token","tomato","tomorrow","tone","tongue","tonight","tool","tooth","top","topic","topple","torch","tornado","tortoise","toss","total","tourist","toward","tower","town","toy","track","trade","traffic","tragic","train","transfer","trap","trash","travel","tray","treat","tree","trend","trial","tribe","trick","trigger","trim","trip","trophy","trouble","truck","true","truly","trumpet","trust","truth","try","tube","tuition","tumble","tuna","tunnel","turkey","turn","turtle","twelve","twenty","twice","twin","twist","two","type","typical","ugly","umbrella","unable","unaware","uncle","uncover","under","undo","unfair","unfold","unhappy","uniform","unique","universe","unknown","unlock","until","unusual","unveil","update","upgrade","uphold","upon","upper","upset","urban","urge","usage","use","used","useful","useless","usual","utility","vacant","vacuum","vague","valid","valley","valve","van","vanish","vapor","various","vast","vault","vehicle","velvet","vendor","venture","venue","verb","verify","version","very","vessel","veteran","viable","vibrant","vicious","victory","video","view","village","vintage","violin","virtual","virus","visa","visit","visual","vital","vivid","vocal","voice","void","volcano","volume","vote","voyage","wage","wagon","wait","walk","wall","walnut","want","warfare","warm","warrior","wash","wasp","waste","water","wave","way","wealth","weapon","wear","weasel","weather","web","wedding","weekend","weird","welcome","west","wet","whale","what","wheat","wheel","when","where","whip","whisper","wide","width","wife","wild","will","win","window","wine","wing","wink","winner","winter","wire","wisdom","wise","wish","witness","wolf","woman","wonder","wood","wool","word","work","world","worry","worth","wrap","wreck","wrestle","wrist","write","wrong","yard","year","yellow","you","young","youth","zebra","zero","zone","zoo"];
        const randomWords = [];
        const random = new Uint16Array(32);
        const limit = 65536 - (65536 % words.length);
        while (randomWords.length < 24) {
            crypto.getRandomValues(random);
            for (const value of random) {
                if (value < limit) randomWords.push(words[value % words.length]);
                if (randomWords.length === 24) break;
            }
        }
        random.fill(0);
        return randomWords;
    }

    /**
     * Utility: Encrypt data with AES-GCM and return Base64 "IV:Ciphertext"
     */
    async _encryptKey(cryptoKey, rawSecretKey) {
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const ciphertext = await crypto.subtle.encrypt(
            { name: "AES-GCM", iv: iv },
            cryptoKey,
            rawSecretKey
        );
        
        // Combine IV + Ciphertext
        const payload = new Uint8Array(12 + ciphertext.byteLength);
        payload.set(iv, 0);
        payload.set(new Uint8Array(ciphertext), 12);
        
        return btoa(String.fromCharCode(...payload));
    }

    /**
     * Utility: Decrypt Base64 "IV:Ciphertext" back to raw bytes
     */
    async _decryptKey(cryptoKey, b64Payload) {
        const payload = Uint8Array.from(atob(b64Payload), c => c.charCodeAt(0));
        const iv = payload.slice(0, 12);
        const ciphertext = payload.slice(12);
        
        return await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv },
            cryptoKey,
            ciphertext
        );
    }

    /**
     * Step 1: Initial Setup of ML-DSA-87 and Passkey PRF.
     */
    async setup({ usePasskey = true } = {}) {
        await this.initPromise;

        const passkey = usePasskey ? await this._getPrfKey(true) : null;
        
        const mnemonic = this._generateMnemonic();
        
        // 3. Generate ML-DSA-87 Keypair in WASM
        const pkPtr = this.module._malloc(this.PK_LEN);
        const skPtr = this.module._malloc(this.SK_LEN);
        
        try {
            if (!pkPtr || !skPtr) throw new Error("Could not allocate signing key memory.");
            const ret = this.module._OQS_SIG_ml_dsa_87_keypair(pkPtr, skPtr);
            if (ret !== 0) throw new Error("Failed to generate PQC keypair");

            const rawPk = this.module.HEAPU8.slice(pkPtr, pkPtr + this.PK_LEN);
            const rawSk = this.module.HEAPU8.subarray(skPtr, skPtr + this.SK_LEN);
            const primaryEnc = passkey ? await this._encryptKey(passkey.key, rawSk) : "";
            const recoveryEnc = await this._wrapRecoveryKey(mnemonic,
                () => this.module.HEAPU8.subarray(skPtr, skPtr + this.SK_LEN));

            const response = await fetch('/api/pki/keys/', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': getCookie('csrftoken')
                },
                body: JSON.stringify({
                    pqc_public_key: btoa(String.fromCharCode(...rawPk)),
                    encrypted_pqc_sk_primary: primaryEnc,
                    encrypted_pqc_sk_recovery: recoveryEnc,
                    credential_id: passkey?.credentialId || "",
                    device_name: navigator.userAgent
                })
            });
            if (!response.ok) throw new Error("Failed to save keys to server.");
            const { id } = await response.json();

            this.lock();
            this.pk = rawPk;
            this.activeKeyId = id;
            this.skPtr = skPtr;
            this.isUnlocked = true;
            this._resetLockTimeout();
            return mnemonic;
        } finally {
            this.module._free(pkPtr);
            if (skPtr && this.skPtr !== skPtr) {
                this.module.HEAPU8.fill(0, skPtr, skPtr + this.SK_LEN);
                this.module._free(skPtr);
            }
        }
    }

    /**
     * Step 2: Unlock the existing key using Passkey PRF.
     */
    async unlock() {
        await this.initPromise;
        
        if (this.isUnlocked) return true;
        
        // 1. Fetch encrypted SK from Backend
        const response = await fetch('/api/pki/keys/active_key/');
        if (response.status === 404) {
            return false; // User has no keys setup
        }
        if (!response.ok) throw new Error("Failed to fetch PQC key metadata");
        
        const keyData = await response.json();
        if (!keyData.encrypted_pqc_sk_primary) {
            throw new Error("Use your recovery phrase to unlock this signing key.");
        }
        
        // 2. Ask WebAuthn to get PRF Symmetric Key
        // Ask for the stored credential when the provider makes it available here.
        const { key } = await this._getPrfKey(false, keyData.credential_id);
        const rawSkBuffer = await this._decryptKey(key, keyData.encrypted_pqc_sk_primary);
        const rawSkArray = new Uint8Array(rawSkBuffer);
        
        try {
            this._loadSigningKey(keyData, rawSkArray);
            return true;
        } finally {
            rawSkArray.fill(0);
        }
    }

    _loadSigningKey(keyData, secret) {
        if (secret.byteLength !== this.SK_LEN) throw new Error("Invalid signing key length.");
        const publicKey = Uint8Array.from(atob(keyData.pqc_public_key), c => c.charCodeAt(0));
        this.lock();
        const ptr = this.module._malloc(this.SK_LEN);
        if (!ptr) throw new Error("Could not allocate signing key memory.");
        this.module.HEAPU8.set(secret, ptr);
        this.skPtr = ptr;
        this.pk = publicKey;
        this.activeKeyId = keyData.id;
        this.isUnlocked = true;
        this._resetLockTimeout();
    }

    async prepareRecoveryReplacement() {
        if (!this.isUnlocked || !this.activeKeyId) throw new Error("Unlock your signing key first.");
        const id = this.activeKeyId;
        const ptr = this.skPtr;
        const mnemonic = this._generateMnemonic();
        const recovery = await this._wrapRecoveryKey(mnemonic, () => {
            if (this.activeKeyId !== id || this.skPtr !== ptr) throw new Error("The signing key was locked or changed.");
            return this.module.HEAPU8.subarray(ptr, ptr + this.SK_LEN);
        });
        return {
            mnemonic,
            save: async () => {
                const response = await fetch(`/api/pki/keys/${id}/`, {
                    method: 'PATCH',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRFToken': getCookie('csrftoken')
                    },
                    body: JSON.stringify({ encrypted_pqc_sk_recovery: recovery })
                });
                if (!response.ok) throw new Error("Failed to replace the recovery phrase.");
            }
        };
    }
    
    /**
     * Recover the Passkey access using the 24-word Mnemonic Phrase.
     * Decrypts the recovery payload, prompts to create a new Passkey, and updates the server.
     */
    async recoverKey(mnemonicString, { replacePasskey = true } = {}) {
        await this.initPromise;
        
        // 1. Get Argon2 Key from Mnemonic
        const mnemonicArray = mnemonicString.trim().split(/\s+/);
        if (mnemonicArray.length !== 24) {
            throw new Error("Invalid Recovery Phrase. Must be exactly 24 words.");
        }
        // 2. Fetch the active key metadata
        const response = await fetch('/api/pki/keys/active_key/');
        if (!response.ok) throw new Error("No active PQC signature key found on the server.");
        const keyData = await response.json();
        
        // 3. Decrypt the recovery blob to get the raw PQC SK
        const rawSkBuffer = await this._unwrapRecoveryKey(mnemonicArray, keyData.encrypted_pqc_sk_recovery);
        const rawSkArray = new Uint8Array(rawSkBuffer);
        
        try {
            if (rawSkArray.byteLength !== this.SK_LEN) throw new Error("Invalid signing key length.");
            if (replacePasskey) {
                const passkey = await this._getPrfKey(true);
                const primary = await this._encryptKey(passkey.key, rawSkArray);
                const patchResponse = await fetch(`/api/pki/keys/${keyData.id}/`, {
                    method: 'PATCH',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRFToken': getCookie('csrftoken')
                    },
                    body: JSON.stringify({
                        encrypted_pqc_sk_primary: primary,
                        credential_id: passkey.credentialId
                    })
                });
                if (!patchResponse.ok) throw new Error("Failed to update the signing passkey on the server.");
            }

            this._loadSigningKey(keyData, rawSkArray);
            return true;
        } finally {
            rawSkArray.fill(0);
        }
    }
    
    /**
     * Check if user has an active key setup on the server
     */
    async hasKeySetup() {
        const response = await fetch('/api/pki/keys/active_key/');
        return response.ok;
    }

    /**
     * Sign a file buffer directly using WASM.
     */
    async signFile(fileBuffer) {
        if (!this.isUnlocked) throw new Error("PQC Key is locked. Call unlock() first.");
        this._resetLockTimeout();
        
        const msgArray = new Uint8Array(fileBuffer);
        const msgLen = msgArray.length;
        
        const msgPtr = this.module._malloc(Math.max(1, msgLen));
        const sigPtr = this.module._malloc(this.SIG_LEN);
        const sigLenPtr = this.module._malloc(4); // size_t
        try {
            if (!msgPtr || !sigPtr || !sigLenPtr) throw new Error("Could not allocate signing memory.");
            this.module.HEAPU8.set(msgArray, msgPtr);
            const ret = this.module._OQS_SIG_ml_dsa_87_sign(sigPtr, sigLenPtr, msgPtr, msgLen, this.skPtr);
            if (ret !== 0) throw new Error("WASM Signature generation failed");

            const actualSigLen = this.module.HEAP32[sigLenPtr >> 2];
            if (actualSigLen !== this.SIG_LEN) throw new Error("Invalid ML-DSA-87 signature length.");
            const sigBytes = this.module.HEAPU8.subarray(sigPtr, sigPtr + actualSigLen);
            let binary = '';
            for (const byte of sigBytes) binary += String.fromCharCode(byte);
            return btoa(binary);
        } finally {
            if (msgPtr) {
                this.module.HEAPU8.fill(0, msgPtr, msgPtr + msgLen);
                this.module._free(msgPtr);
            }
            this.module._free(sigPtr);
            this.module._free(sigLenPtr);
        }
    }

    /**
     * Verify a file buffer against a signature and public key.
     */
    async verifySignature(fileBuffer, sigBase64, pkBase64) {
        await this.initPromise;
        
        const msgArray = new Uint8Array(fileBuffer);
        return this.verifySignatureRaw(msgArray, sigBase64, pkBase64);
    }
    
    /**
     * Internal method to verify any Uint8Array payload against a signature and public key.
     */
    async verifySignatureRaw(msgArray, sigBase64, pkBase64) {
        await this.initPromise;
        const msgLen = msgArray.length;
        
        const sigArray = Uint8Array.from(atob(sigBase64), c => c.charCodeAt(0));
        const pkArray = Uint8Array.from(atob(pkBase64), c => c.charCodeAt(0));
        
        const msgPtr = this.module._malloc(msgLen);
        if (msgPtr === 0) throw new Error("WASM Memory Allocation Failed!");
        
        this.module.HEAPU8.set(msgArray, msgPtr);
        
        const sigPtr = this.module._malloc(sigArray.length);
        this.module.HEAPU8.set(sigArray, sigPtr);
        
        const pkPtr = this.module._malloc(this.PK_LEN);
        this.module.HEAPU8.set(pkArray, pkPtr);
        
        const ret = this.module._OQS_SIG_ml_dsa_87_verify(msgPtr, msgLen, sigPtr, sigArray.length, pkPtr);
        
        this.module._free(msgPtr);
        this.module._free(sigPtr);
        this.module._free(pkPtr);
        
        return ret === 0;
    }

    /**
     * Verify TSA Signature from the Server
     */
    async verifyTSASignature(fileBuffer, userSignature, timestampIso, tsaSignatureBase64) {
        if (!window.ROOT_CA_PUBLIC_KEY) {
            console.warn("ROOT_CA_PUBLIC_KEY not found!");
            return false;
        }
        
        // sha3_256 returns a hex string directly when passed a buffer/string
        const fileHashHex = typeof sha3_256 !== 'undefined' ? sha3_256(fileBuffer) : '';
        
        // Construct the EXACT JSON string that the python backend generated:
        // json.dumps(payload_dict, separators=(',', ':'), sort_keys=True)
        const payloadStr = `{"file_hash":"${fileHashHex}","issuer":"CyberFortress-TSA","timestamp":"${timestampIso}","user_signature":"${userSignature}"}`;
        const encoder = new TextEncoder();
        const payloadArray = encoder.encode(payloadStr);
        
        return this.verifySignatureRaw(payloadArray, tsaSignatureBase64, window.ROOT_CA_PUBLIC_KEY);
    }
    
    /**
     * Verify CA Signature of a User Key
     */
    async verifyCASignature(username, userPkBase64, caSignatureBase64) {
        if (!window.ROOT_CA_PUBLIC_KEY) return false;
        
        const payloadStr = `{"issuer":"CyberFortress-RootCA","public_key":"${userPkBase64}","user":"${username}"}`;
        const encoder = new TextEncoder();
        const payloadArray = encoder.encode(payloadStr);
        
        return this.verifySignatureRaw(payloadArray, caSignatureBase64, window.ROOT_CA_PUBLIC_KEY);
    }
}

// Global instance
const pqcManager = new PqcManager();

function showRecoveryPhrase(mnemonic, save = null) {
    const modal = document.getElementById('pqc-mnemonic-modal');
    const download = document.getElementById('btn-download-mnemonic');
    const saved = document.getElementById('btn-mnemonic-saved');
    const cancel = document.getElementById('btn-mnemonic-cancel');
    const status = document.getElementById('pqc-mnemonic-status');
    status.textContent = '';
    cancel.classList.toggle('hidden', !save);

    const close = () => {
        download.onclick = saved.onclick = cancel.onclick = null;
        mnemonic.fill('');
        modal.classList.add('hidden');
    };
    download.onclick = () => {
        const url = URL.createObjectURL(new Blob([mnemonic.join(' ') + '\n'], { type: 'text/plain' }));
        const link = document.createElement('a');
        link.href = url;
        link.download = 'cloud-policy-recovery-phrase.txt';
        document.body.appendChild(link);
        link.click();
        link.remove();
        URL.revokeObjectURL(url);
    };
    cancel.onclick = close;
    saved.onclick = async () => {
        saved.disabled = cancel.disabled = true;
        status.textContent = '';
        try {
            if (save) await save();
            close();
            if (window.pqcSetupPromiseResolve) {
                window.pqcSetupPromiseResolve();
                window.pqcSetupPromiseResolve = null;
                window.pqcSetupPromiseReject = null;
            } else {
                window.location.reload();
            }
        } catch (error) {
            status.textContent = error.message;
        } finally {
            saved.disabled = cancel.disabled = false;
        }
    };
    modal.classList.remove('hidden');
}

// Event Listeners for UI Modals (Hooked up if they exist on the page)
function openPqcSetup() {
    const status = document.getElementById('pqc-setup-status');
    status.textContent = '';
    status.classList.add('hidden');
    document.getElementById('btn-pqc-setup').textContent = 'Choose a passkey';
    document.getElementById('pqc-setup-modal').classList.remove('hidden');
}

document.addEventListener('DOMContentLoaded', () => {
    const btnSetup = document.getElementById('btn-pqc-setup');
    const btnSetupRecovery = document.getElementById('btn-pqc-setup-recovery');
    const setupModal = document.getElementById('pqc-setup-modal');
    const setupStatus = document.getElementById('pqc-setup-status');
    const btnSetupClose = document.getElementById('btn-pqc-setup-close');
    
    const unlockModal = document.getElementById('pqc-unlock-modal');
    const btnUnlock = document.getElementById('btn-pqc-unlock');
    const btnUnlockCancel = document.getElementById('btn-pqc-cancel');
    const unlockStatus = document.getElementById('pqc-unlock-status');
    const btnRecover = document.getElementById('btn-pqc-recover');
    
    const recoverModal = document.getElementById('pqc-recover-modal');
    const btnRecoverClose = document.getElementById('btn-pqc-recover-close');
    const btnDoRecover = document.getElementById('btn-pqc-do-recover');
    const btnRecoverOnly = document.getElementById('btn-pqc-recover-only');
    const recoverStatus = document.getElementById('pqc-recover-status');
    const recoverPhrase = document.getElementById('pqc-recover-phrase');
    
    if (btnSetup && btnSetupRecovery && btnSetupClose) {
        const setup = async (event) => {
            const usePasskey = event.currentTarget === btnSetup;
            try {
                btnSetup.disabled = btnSetupRecovery.disabled = btnSetupClose.disabled = true;
                setupStatus.classList.remove('hidden');
                setupStatus.textContent = usePasskey ? "Waiting for your passkey…" : "Creating your signing key…";
                const mnemonic = await pqcManager.setup({ usePasskey });
                setupModal.classList.add('hidden');
                showRecoveryPhrase(mnemonic);
            } catch (e) {
                if (e.name === 'NotSupportedError') {
                    setupStatus.textContent = e.message + " No signing key was created. You can choose another provider or use a recovery phrase.";
                    btnSetup.textContent = 'Try another passkey provider';
                } else {
                    setupStatus.textContent = e.name === 'NotAllowedError' ? "The passkey prompt ended. Try again or use a recovery phrase." : e.message;
                }
            } finally {
                btnSetup.disabled = btnSetupRecovery.disabled = btnSetupClose.disabled = false;
            }
        };
        btnSetup.addEventListener('click', setup);
        btnSetupRecovery.addEventListener('click', setup);
    }
    
    if (btnSetupClose) {
        btnSetupClose.addEventListener('click', () => {
            setupModal.classList.add('hidden');
            if (window.pqcSetupPromiseReject) {
                window.pqcSetupPromiseReject(new Error("User cancelled Passkey setup"));
                window.pqcSetupPromiseReject = null;
            }
        });
    }
    
    if (btnUnlockCancel) {
        btnUnlockCancel.addEventListener('click', () => {
            unlockModal.classList.add('hidden');
            if (window.pqcUnlockPromiseReject) {
                window.pqcUnlockPromiseReject(new Error("User cancelled Passkey unlock"));
                window.pqcUnlockPromiseReject = null;
            }
        });
    }
    
    if (btnUnlock) {
        btnUnlock.addEventListener('click', async () => {
            try {
                btnUnlock.disabled = true;
                btnUnlock.textContent = "Waiting for Passkey...";
                unlockStatus.classList.add('hidden');
                
                await pqcManager.unlock();
                
                unlockModal.classList.add('hidden');
                btnUnlock.disabled = false;
                btnUnlock.textContent = "Unlock with Passkey";
                
                if (window.pqcUnlockPromiseResolve) {
                    window.pqcUnlockPromiseResolve();
                    window.pqcUnlockPromiseResolve = null;
                }
            } catch (e) {
                console.error(e);
                if (e.message.includes('timed out or was not allowed') || e.message.includes('cancelled')) {
                    // Suppress WebAuthn cancellation errors to avoid scaring the user
                    unlockStatus.classList.add('hidden');
                } else {
                    unlockStatus.textContent = "Authentication failed: " + e.message;
                    unlockStatus.classList.remove('hidden');
                }
                btnUnlock.disabled = false;
                btnUnlock.textContent = "Try Again";
            }
        });
    }
    
    // Bind Recovery Modal toggle
    if (btnRecover) {
        btnRecover.addEventListener('click', () => {
            unlockModal.classList.add('hidden');
            if (recoverModal) recoverModal.classList.remove('hidden');
        });
    }
    
    if (btnRecoverClose) {
        btnRecoverClose.addEventListener('click', () => {
            recoverModal.classList.add('hidden');
            recoverPhrase.value = '';
            if (window.pqcUnlockPromiseReject) {
                window.pqcUnlockPromiseReject(new Error("User cancelled recovery"));
                window.pqcUnlockPromiseReject = null;
            }
        });
    }
    
    if (btnDoRecover && btnRecoverOnly) {
        const recover = async (event) => {
            const button = event.currentTarget;
            const label = button.textContent;
            try {
                const phrase = recoverPhrase.value;
                if (!phrase || phrase.trim().split(/\s+/).length !== 24) {
                    throw new Error("Please enter exactly 24 words.");
                }
                
                btnDoRecover.disabled = true;
                btnRecoverOnly.disabled = true;
                button.textContent = "Unlocking…";
                recoverStatus.classList.add('hidden');
                
                await pqcManager.recoverKey(phrase, { replacePasskey: button === btnDoRecover });
                
                recoverModal.classList.add('hidden');
                recoverPhrase.value = '';
                
                // Once recovered, they are unlocked
                if (window.pqcUnlockPromiseResolve) {
                    window.pqcUnlockPromiseResolve();
                    window.pqcUnlockPromiseResolve = null;
                }
                
                document.dispatchEvent(new CustomEvent('pqcKeyRecovered', {
                    detail: { replacedPasskey: button === btnDoRecover }
                }));
            } catch (e) {
                recoverStatus.textContent = "Recovery failed: " + e.message +
                    (e.name === 'NotSupportedError' ? " Try another provider or unlock with the phrase only." : "");
                recoverStatus.classList.remove('hidden');
            } finally {
                btnDoRecover.disabled = false;
                btnRecoverOnly.disabled = false;
                button.textContent = label;
            }
        };
        btnDoRecover.addEventListener('click', recover);
        btnRecoverOnly.addEventListener('click', recover);
    }
});

/**
 * Helper function to wait for user to unlock via Modal
 */
async function requirePqcUnlock() {
    if (window.ENABLE_PQC_FEATURES === false) return true;
    if (pqcManager.isUnlocked) return true;
    
    const hasSetup = await pqcManager.hasKeySetup();
    if (!hasSetup) {
        openPqcSetup();
        return new Promise((resolve, reject) => {
            window.pqcSetupPromiseResolve = resolve;
            window.pqcSetupPromiseReject = reject;
        });
    }
    
    document.getElementById('pqc-unlock-modal').classList.remove('hidden');
    return new Promise((resolve, reject) => {
        window.pqcUnlockPromiseResolve = resolve;
        window.pqcUnlockPromiseReject = reject;
    });
}
