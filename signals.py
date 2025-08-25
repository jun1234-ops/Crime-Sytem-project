from django.apps import apps
from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType
from django.db.models.signals import post_migrate
from django.dispatch import receiver

@receiver(post_migrate)
def create_user_roles(sender, **kwargs):
    if sender.name == 'core':  # Run only for the core app
        # Define the groups
        roles = ['Admin', 'Officer', 'Viewer']
        for role in roles:
            group, created = Group.objects.get_or_create(name=role)
            if created:
                print(f'Created role: {role}')

        # Optional: You can assign permissions to each role here if needed
