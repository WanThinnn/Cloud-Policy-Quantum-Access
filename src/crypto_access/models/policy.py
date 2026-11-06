"""
AccessPolicy Model (BM7)
Stores ABAC policy rules in database for PyCasbin
"""

from django.db import models
from django.contrib.auth.models import User
from .base import BaseModel


class AccessPolicy(BaseModel):
    """
    Access Policy for ABAC (BM7)
    Defines who can access what resources under which conditions
    """
    EFFECT_CHOICES = [
        ('allow', '✅ Allow'),
        ('deny', '❌ Deny'),
    ]
    
    RESOURCE_CHOICES = [
        ('document', '📄 Document'),
        ('key', '🔑 Key Revocation List'),
        ('user', '👤 Manage users'),
        ('policy', '📋 Manage policies'),
        ('attribute', '🏷️ Attribute management'),
        ('audit', '📊 System log'),
        ('*', '⭐ All resources (*)'),
    ]
    
    ACTION_CHOICES = [
        ('read', '👁️ View'),
        ('write', '✏️ Create'),
        ('update', '📝 Update'),
        ('delete', '🗑️ Delete'),
        ('upload', '⬆️ Upload'),
        ('download', '⬇️ Download'),
        ('encrypt', '🔒 Encryption'),
        ('decrypt', '🔓 Decrypt'),
        ('*', '⭐ All actions (*)'),
    ]
    
    name = models.CharField(
        max_length=100,
        unique=True,
        help_text="Policy name for identification"
    )
    description = models.TextField(
        blank=True,
        help_text="Description of what this policy does"
    )
    
    # Subject condition (ABAC expression)
    # Examples:
    # - "r.sub.user_type == 'admin'"
    # - "r.sub.department == 'it' && r.sub.clearance_level >= 'secret'"
    # - "r.sub.role in ['manager', 'director']"
    subject_condition = models.TextField(
        help_text="ABAC condition expression using r.sub attributes. Example: r.sub.department == 'it'"
    )
    
    cpabe_policy = models.CharField(
        max_length=500,
        blank=True,
        null=True,
        help_text="Equivalent CP-ABE policy string. Example: (department:it and clearance_level:secret)"
    )
    
    # Resource and Action
    resource = models.CharField(
        max_length=255,
        help_text="Resource this policy applies to"
    )
    action = models.CharField(
        max_length=50,
        choices=ACTION_CHOICES,
        help_text="Action this policy permits/denies"
    )
    
    # Effect
    effect = models.CharField(
        max_length=10,
        choices=EFFECT_CHOICES,
        default='allow',
        help_text="Whether to allow or deny this access"
    )
    
    # Priority (lower = higher priority)
    priority = models.IntegerField(
        default=100,
        help_text="Policy priority (lower number = higher priority)"
    )
    
    # Status
    is_active = models.BooleanField(
        default=True,
        help_text="Whether this policy is active"
    )
    
    # Audit fields
    created_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        related_name='created_policies',
        help_text="Admin who created this policy"
    )
    
    def __str__(self):
        return f"{self.name}: {self.subject_condition} -> {self.resource}/{self.action} ({self.effect})"
    
    def to_casbin_policy(self):
        """Convert to Casbin policy format: [sub_rule, obj, act, eft]"""
        return [self.subject_condition, self.resource, self.action, self.effect]
        
    def _generate_cpabe_policy(self):
        """Auto-generate CP-ABE policy from ABAC subject_condition"""
        if not self.subject_condition:
            return ""

        from django.conf import settings
        if getattr(settings, 'CPABE_SCHEME', 'ac17').strip().lower() == 'covercrypt':
            return self._generate_covercrypt_policy()

        from crypto_access.services.abe_schemes import validate_scheme
        scheme = validate_scheme(getattr(settings, 'CPABE_SCHEME', 'ac17'))
            
        import ast
        
        expr = self.subject_condition.replace('&&', ' and ').replace('||', ' or ')
        try:
            tree = ast.parse(expr, mode='eval')
        except SyntaxError:
            return ""
            
        def _build_rabe(node):
            if isinstance(node, ast.BoolOp):
                op_str = 'and' if isinstance(node.op, ast.And) else 'or'
                res = _build_rabe(node.values[0])
                for child in node.values[1:]:
                    res = f"({res} {op_str} {_build_rabe(child)})"
                return res
            elif isinstance(node, ast.Compare):
                attr_node = node.left
                if isinstance(attr_node, ast.Attribute):
                    attr = attr_node.attr
                else:
                    attr = attr_node.id
                attr = attr.replace('r.sub.', '')
                
                op_node = node.ops[0]
                val_node = node.comparators[0]
                
                if isinstance(op_node, ast.In):
                    if hasattr(val_node, 'elts') and val_node.elts:
                        values = [v.value if isinstance(v, ast.Constant) else str(v) for v in val_node.elts]
                        res = f"{attr}:{values[0]}"
                        for v in values[1:]:
                            res = f"({res} or {attr}:{v})"
                        return res
                    return ""
                elif isinstance(op_node, ast.Eq):
                    val = val_node.value if isinstance(val_node, ast.Constant) else str(val_node)
                    return f"{attr}:{val}"
                elif isinstance(op_node, ast.NotEq) or isinstance(op_node, ast.NotIn):
                    from crypto_access.models import AttributeDefinition

                    if scheme == 'tkn20':
                        # TKN20 supports native negation
                        if isinstance(op_node, ast.NotEq):
                            val = val_node.value if isinstance(val_node, ast.Constant) else str(val_node)
                            return f"not {attr}:{val}"
                        else:
                            if hasattr(val_node, 'elts') and val_node.elts:
                                excluded = [v.value if isinstance(v, ast.Constant) else str(v) for v in val_node.elts]
                                res = f"not {attr}:{excluded[0]}"
                                for v in excluded[1:]:
                                    res = f"({res} and not {attr}:{v})"
                                return res
                            return ""
                    
                    try:
                        attr_def = AttributeDefinition.objects.get(name=attr)
                        allowed = attr_def.allowed_values
                        
                        if isinstance(op_node, ast.NotEq):
                            excluded = [val_node.value if isinstance(val_node, ast.Constant) else str(val_node)]
                        else:
                            if hasattr(val_node, 'elts') and val_node.elts:
                                excluded = [v.value if isinstance(v, ast.Constant) else str(v) for v in val_node.elts]
                            else:
                                excluded = []
                                
                        positive_vals = [v for v in allowed if v not in excluded]
                        if not positive_vals:
                            return ""
                            
                        res = f"{attr}:{positive_vals[0]}"
                        for v in positive_vals[1:]:
                            res = f"({res} or {attr}:{v})"
                        return res
                    except Exception:
                        return ""
                else:
                    val = val_node.value if isinstance(val_node, ast.Constant) else str(val_node)
                    return f"{attr}:{val}"
                    
            return ""

        return _build_rabe(tree.body)

    def _generate_covercrypt_policy(self):
        """Compile the safe ABAC subset to the upstream dimension::value grammar."""
        import ast
        from crypto_access.services.covercrypt_config import (
            CoverCryptConfigurationError,
            build_covercrypt_configuration,
        )

        try:
            configuration = build_covercrypt_configuration()
        except CoverCryptConfigurationError as exc:
            raise ValueError(f"CoverCrypt dimension configuration is invalid: {exc}") from exc

        dimensions = {item['name']: set(item['attributes']) for item in configuration.dimensions}
        expression = self.subject_condition.replace('&&', ' and ').replace('||', ' or ').strip()
        try:
            tree = ast.parse(expression, mode='eval')
        except SyntaxError as exc:
            raise ValueError("Invalid ABAC condition syntax for CoverCrypt.") from exc

        def attribute_name(node):
            if not isinstance(node, ast.Attribute) or not isinstance(node.value, ast.Attribute):
                raise ValueError("CoverCrypt conditions must reference r.sub.<dimension> attributes.")
            if not isinstance(node.value.value, ast.Name) or node.value.value.id != 'r' or node.value.attr != 'sub':
                raise ValueError("CoverCrypt conditions must reference r.sub.<dimension> attributes.")
            name = node.attr
            if name not in dimensions:
                raise ValueError(f"Attribute '{name}' is not a configured CoverCrypt dimension.")
            return name

        def literal_value(node):
            if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
                raise ValueError("CoverCrypt comparisons require string literals.")
            return node.value

        def compile_node(node):
            if isinstance(node, ast.BoolOp) and isinstance(node.op, (ast.And, ast.Or)):
                operator = '&&' if isinstance(node.op, ast.And) else '||'
                compiled = [compile_node(child) for child in node.values]
                return '(' + f' {operator} '.join(compiled) + ')'

            if isinstance(node, ast.Compare):
                if len(node.ops) != 1 or len(node.comparators) != 1:
                    raise ValueError("Chained comparisons are not supported by CoverCrypt policy compilation.")
                dimension = attribute_name(node.left)
                operator = node.ops[0]
                value_node = node.comparators[0]
                if isinstance(operator, ast.Eq):
                    values = [literal_value(value_node)]
                elif isinstance(operator, ast.In):
                    if not isinstance(value_node, (ast.List, ast.Tuple, ast.Set)) or not value_node.elts:
                        raise ValueError("CoverCrypt 'in' requires a non-empty literal list, tuple, or set.")
                    values = [literal_value(item) for item in value_node.elts]
                    if len(values) != len(set(values)):
                        raise ValueError("Duplicate values are ambiguous in a CoverCrypt 'in' condition.")
                elif isinstance(operator, (ast.NotEq, ast.NotIn)):
                    raise ValueError(
                        "CoverCrypt does not support != or not in with CPQA's missing-attribute semantics."
                    )
                else:
                    raise ValueError("CoverCrypt supports only == and in comparisons for enum attributes.")

                invalid = [value for value in values if value not in dimensions[dimension]]
                if invalid:
                    raise ValueError(
                        f"Value(s) {invalid!r} are not configured for CoverCrypt dimension '{dimension}'."
                    )
                atoms = [f'{dimension}::{value}' for value in values]
                return atoms[0] if len(atoms) == 1 else '(' + ' || '.join(atoms) + ')'

            raise ValueError(f"Unsupported CoverCrypt policy expression: {type(node).__name__}.")

        policy = compile_node(tree.body)
        if len(policy) > 500:
            raise ValueError("Compiled CoverCrypt policy exceeds the 500-character CPQA policy limit.")
        return policy

    def save(self, *args, **kwargs):
        if self.subject_condition:
            self.cpabe_policy = self._generate_cpabe_policy()
        super().save(*args, **kwargs)
    
    class Meta:
        db_table = 'crypto_access_policies'
        verbose_name = 'Access Policy'
        verbose_name_plural = 'Access Policies'
        ordering = ['priority', 'name']
