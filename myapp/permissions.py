from rest_framework.permissions import IsAuthenticated, BasePermission
from rest_framework import permissions 
from .models import User


class IsAdmin(BasePermission):
    '''Allow access only to admin'''

    def has_permission(self, request, view):
        # return request.user and request.user.groups.filter(role='Admin').exists()
        return bool(request.user.role == "admin")
    

class IsManager(BasePermission):
    '''Allow access only to manager'''

    def has_permission(self, request, view):
        return bool(request.user.role == "manager")
    

class IsSupportStaff(BasePermission):
    '''Allow access only to support staff'''

    def has_permission(self, request, view):
        return bool(request.user.role == "support_staff")
    

class IsClient(BasePermission):
    '''Allow access only to client'''

    def has_permission(self, request, view):
        return bool(request.user.role=="client")


class IsC(BasePermission):
    """
    Custom permission to only allow access for clients.
    """
    # def has_permission(self, request, view):
    #     return bool(request.Client)
    
    def has_permission(self, request, view):
        return bool(request.user.role == "client")
        # print(request.user.groups.filter(role='client').exists(),"dfsf")
        # return request.user and request.user.groups.filter(role='Client').exists()


class IsViewer(BasePermission):
    '''Allow access only to viewer'''

    def has_permission(self, request, view):
        return bool(request.user.role == "viewer")



class IsUser(permissions.BasePermission):
    """
    Custom permission to only allow access for User users.
    """
    def has_permission(self, request, view):
        return request.user and request.user.groups.filter(name='User').exists()
    



    # def has_permission(self, request, view):
    #     return bool(request.client)
    
    # def has_permission(self, request, view):
    #     user = request.user
    #     if user.role == 'client':
    #         return True
    #     return False
    
    # def has_permission(self, request, view): 
    #     return request.user and request.user.groups.filter(role='client').exists()

    

    # def has_permission(self, request, view):
    #     return request.user and request.user.groups.filter(role='client').exists()
















# from rest_framework.views import APIView
# from rest_framework.response import Response
# from rest_framework.permissions import IsAuthenticated
# from .permissions import IsAdmin

# class AdminOnlyView(APIView):
#     permission_classes = [IsAuthenticated, IsAdmin]  

#     def get(self, request):
#         return Response({"message": "Welcome, Admin!"})
