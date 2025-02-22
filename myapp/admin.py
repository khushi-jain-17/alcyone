from django.contrib import admin
# from django.contrib.auth.admin import UserAdmin 
from .models import User, Ticket, Log


@admin.register(User)
class CustomUserAdmin(admin.ModelAdmin):
    """Admin for User"""
    list_display = ('username', 'email', 'role')
    ordering = ('email',)




admin.site.register(Ticket)
admin.site.register(Log)


