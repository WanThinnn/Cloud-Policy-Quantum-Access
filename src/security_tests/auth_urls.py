"""HTTP harness with the real JWT middleware, ABAC middleware and production URL modules."""
from django.contrib.auth.models import AnonymousUser
from django.urls import include, path


class AnonymousMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        request.user = AnonymousUser()
        return self.get_response(request)


urlpatterns = [
    path('api/auth/', include('crypto_access.urls.auth')),
    path('api/pki/', include('crypto_access.urls.pki')),
    path('', include('security_tests.urls')),
]
