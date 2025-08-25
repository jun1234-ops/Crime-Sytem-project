from .models import ActivityLog

def log_activity(user, action):
    ActivityLog.objects.create(user=user, action=action)
