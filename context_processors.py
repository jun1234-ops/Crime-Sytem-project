def user_groups_processor(request):
    if request.user.is_authenticated:
        from django.contrib.auth.models import Group  # 👈 Import inside the function
        return {'user_groups': request.user.groups.all()}
    return {'user_groups': []}
