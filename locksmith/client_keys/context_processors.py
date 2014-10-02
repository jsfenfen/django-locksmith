from locksmith.client_keys.common import get_client_key, get_cached_client_key
from django.conf import settings

def client_key_context(request):
    if hasattr(settings, 'LOCKSMITH_CLIENT_KEY'):
        ua = request.META.get("HTTP_USER_AGENT", "")
        if not ua:
            return {}
        user_agent = ua[:8].upper()
        return {
            'CLIENT_KEY': lambda: get_cached_client_key(settings.LOCKSMITH_CLIENT_KEY, request.get_host(), user_agent)
        }
    else:
        return {}