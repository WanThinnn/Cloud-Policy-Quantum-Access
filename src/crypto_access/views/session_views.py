from rest_framework import viewsets, mixins, status
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from django.shortcuts import render
from ..models import ActiveSession
from ..services.session_service import session_key
from ..serializers.session import ActiveSessionSerializer

class SessionViewSet(viewsets.GenericViewSet, mixins.ListModelMixin):
    """
    ViewSet for users to view and revoke their active sessions.
    """
    serializer_class = ActiveSessionSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        return ActiveSession.objects.filter(user=self.request.user, is_active=True).order_by('-last_active')
        
    @action(detail=False, methods=['post'])
    def revoke_all(self, request):
        """Revoke all sessions except the current one"""
        current_jti = session_key(request.auth) if request.auth is not None else None

        qs = ActiveSession.objects.filter(user=request.user, is_active=True)
        if current_jti:
            qs = qs.exclude(session_key=current_jti)
            
        count = qs.update(is_active=False)
        return Response({'message': f'Revoked {count} other sessions'})

    @action(detail=True, methods=['post'])
    def revoke(self, request, pk=None):
        """Revoke a specific session"""
        try:
            session = ActiveSession.objects.get(pk=pk, user=request.user, is_active=True)
            session.is_active = False
            session.save(update_fields=['is_active'])
            return Response({'message': 'Session revoked successfully'})
        except ActiveSession.DoesNotExist:
            return Response({'error': 'Session not found'}, status=status.HTTP_404_NOT_FOUND)

def sessions_page(request):
    """Render sessions management page"""
    return render(request, 'accounts/sessions.html')
