from turtle import update
from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from .models import Ticket, Log, User




@receiver(post_save, sender=Ticket)
def log_ticket_creation(sender, instance, created, **kwargs):
    if created:
        Log.objects.create(
            user=instance.created_by,  
            action='CREATE',
            description=f"Ticket '{instance.title}' created by {instance.created_by.username}",  
        )
      

@receiver(post_save, sender=Ticket)
def log_ticket_updation(sender, instance, created, **kwargs):
    # action = 'UPDATE'
    # description = f"Ticket '{instance.title}' updated by {instance.created_by.username}"
    if created:
        Log.objects.create(
            user=instance.created_by,  
            action='UPDATE',
            description=f"Ticket '{instance.title}' updated by {instance.created_by.username}",  
        )


@receiver(post_delete, sender=Ticket)
def log_ticket_deletion(sender, instance, **kwargs):
    user = instance.created_by
    if isinstance(user, User):
        print(f"Ticket '{instance.title}' was deleted by {user.username}")
    else:
        print(f"Ticket '{instance.title}' was deleted by {user}")

    # user = instance.deleted_by  
    # print(f"Ticket '{instance.title}' was deleted by {user}")

    # Log.objects.create(
    #     user=instance.created_by,
    #     action='DELETE',
    #     description=f"Ticket '{instance.title}' deleted by {instance.created_by.username}"
    # )


@receiver(post_save, sender=Ticket)
def log_ticket_view(sender, instance, created, **kwargs):
    # action = 'UPDATE'
    # description = f"Ticket '{instance.title}' updated by {instance.created_by.username}"
    if created:
        Log.objects.create(
            user=instance.created_by,  
            action='VIEW',
            description=f"Ticket '{instance.title}' viewed by {instance.created_by.username}",  
        )