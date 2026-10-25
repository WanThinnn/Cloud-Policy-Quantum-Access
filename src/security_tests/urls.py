from django.urls import include, path
from rest_framework.routers import DefaultRouter
from crypto_access.views.storage import UploadedFileViewSet

router = DefaultRouter()
router.register('files', UploadedFileViewSet, basename='security-file')
urlpatterns = [path('api/storage/', include(router.urls))]
