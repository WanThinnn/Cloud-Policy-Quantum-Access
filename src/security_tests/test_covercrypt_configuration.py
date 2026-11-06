from django.contrib.auth.models import User
from django.test import TestCase, override_settings
from rest_framework.test import APIRequestFactory, force_authenticate

from crypto_access.models import AccessPolicy, AttributeDefinition, UserProfile
from crypto_access.services.cpabe_service import CPABEService
from crypto_access.services.covercrypt_config import (
    CoverCryptConfigurationError,
    build_covercrypt_configuration,
    build_keyset_manifest,
    verify_keyset_manifest,
)
from crypto_access.views.covercrypt import covercrypt_configuration


class CoverCryptConfigurationTests(TestCase):
    def setUp(self):
        definitions = [
            ("department", ["hr", "it"]),
            ("role", ["employee", "manager"]),
            ("clearance_level", ["public", "confidential", "secret", "top_secret"]),
            ("data_access", ["basic", "advanced", "full"]),
            ("employment_status", ["active", "inactive"]),
        ]
        for name, values in definitions:
            AttributeDefinition.objects.create(
                name=name,
                display_name=name.replace("_", " ").title(),
                data_type="enum",
                allowed_values=values,
            )

    def test_configuration_uses_ordered_deployment_dimensions(self):
        configuration = build_covercrypt_configuration()

        self.assertEqual(
            [dimension["name"] for dimension in configuration.dimensions],
            ["clearance_level", "data_access", "department", "employment_status", "role", "user_type"],
        )
        self.assertFalse(any(dimension["hierarchical"] for dimension in configuration.dimensions))
        self.assertTrue(configuration.fingerprint.startswith("sha256:"))

    @override_settings(CPABE_SCHEME="covercrypt")
    def test_covercrypt_policy_compiles_equality_membership_and_grouping(self):
        policy = AccessPolicy(subject_condition=(
            "(r.sub.department == 'it' or r.sub.department in ['hr', 'finance']) "
            "and r.sub.user_type == 'data_owner'"
        ))

        self.assertEqual(
            policy._generate_cpabe_policy(),
            "((department::it || (department::hr || department::finance)) && user_type::data_owner)",
        )

    @override_settings(CPABE_SCHEME="covercrypt")
    def test_covercrypt_rejects_negative_unknown_and_unconfigured_conditions(self):
        unsupported = [
            "r.sub.department != 'it'",
            "r.sub.department not in ['it']",
            "r.sub.department == 'unknown'",
            "r.sub.username == 'alice'",
            "r.sub.clearance_level >= 'secret'",
        ]
        for condition in unsupported:
            with self.subTest(condition=condition), self.assertRaises(ValueError):
                AccessPolicy(subject_condition=condition)._generate_cpabe_policy()

    def test_covercrypt_mapper_requires_every_dimension_and_exact_values(self):
        attrs = {
            "department": "it",
            "role": "employee",
            "clearance_level": "secret",
            "data_access": "basic",
            "employment_status": "active",
            "user_type": "data_user",
        }
        mapped = CPABEService.expand_hierarchical_attributes(None, attrs, scheme="covercrypt")
        self.assertIn("department::it", mapped)
        self.assertIn("user_type::data_user", mapped)

        with self.assertRaisesRegex(Exception, "missing required CoverCrypt dimensions"):
            CPABEService.expand_hierarchical_attributes(None, {"department": "it"}, scheme="covercrypt")

        attrs["department"] = "unknown"
        with self.assertRaisesRegex(Exception, "outside the CoverCrypt dimension"):
            CPABEService.expand_hierarchical_attributes(None, attrs, scheme="covercrypt")

    def test_manifest_rejects_configuration_mismatch(self):
        configuration = build_covercrypt_configuration()
        manifest = build_keyset_manifest("primary", "abe_covercrypt", configuration)
        manifest["config_fingerprint"] = "sha256:wrong"

        with self.assertRaises(CoverCryptConfigurationError):
            verify_keyset_manifest(manifest, "primary", "abe_covercrypt", configuration)

    def test_super_admin_only_configuration_endpoint(self):
        regular_user = User.objects.create_user("regular", password="unused")
        UserProfile.objects.create(user=regular_user, user_type="data_viewer")
        super_admin = User.objects.create_user("super", password="unused")
        UserProfile.objects.create(user=super_admin, user_type="super_admin")
        factory = APIRequestFactory()

        # The isolated security-test settings have no authentication classes,
        # so DRF returns 403 for an anonymous permission failure.
        self.assertEqual(covercrypt_configuration(factory.get("/configuration/")).status_code, 403)
        regular_request = factory.get("/configuration/")
        force_authenticate(regular_request, regular_user)
        self.assertEqual(covercrypt_configuration(regular_request).status_code, 403)
        super_admin_request = factory.get("/configuration/")
        force_authenticate(super_admin_request, super_admin)
        response = covercrypt_configuration(super_admin_request)
        self.assertEqual(response.status_code, 200)
        self.assertIn("fingerprint", response.data)
