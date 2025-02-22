from django.shortcuts import render
from .models import User, Client, Ticket, Log
from .serializers import  SignupSerializer, LoginSerializer, UserSerializer, ClientSerializer, TicketSerializer
from rest_framework import status, generics
from rest_framework.response import Response
from rest_framework.generics import CreateAPIView, ListAPIView, RetrieveAPIView, UpdateAPIView, DestroyAPIView
from .permissions import IsAdmin, IsManager ,IsSupportStaff, IsClient, IsViewer, IsC
from rest_framework.views import APIView
from django.contrib.auth import authenticate, login 
from django.http import JsonResponse
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.authentication import SessionAuthentication, BasicAuthentication
from rest_framework.exceptions import AuthenticationFailed
import jwt
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.response import Response
from .auth import generate_access_token, generate_refresh_token
from django.contrib.auth.models import User
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.views import TokenObtainPairView
from django.contrib.auth.hashers import make_password
from django.db.models import Q
import logging 
from django.utils import timezone
from rest_framework.exceptions import PermissionDenied



class CreateTicketAPIView(generics.CreateAPIView):
    authentication_classes = [JWTAuthentication]
    queryset = Ticket.objects.all()
    serializer_class = TicketSerializer

    def perform_create(self, serializer):
        user = self.request.user
        print("user",user)
        if not user.is_authenticated:
            raise PermissionDenied("Authentication is required to create a ticket.")
    
        ticket = serializer.save(created_by=user, user=user)
        print("Tick",ticket)     
        Log.objects.create(
            user=user,  
            action='CREATE',
            ticket=ticket,
            description=f"Ticket '{ticket.title}' created by {ticket.created_by}",
        )
        return ticket

    def create(self, request, *args, **kwargs):
        response = super().create(request, *args, **kwargs)
        return Response(
            {
                'ticket': response.data,
                'message': 'Ticket created successfully and logged.'
            },
            status=status.HTTP_201_CREATED
        )


class TicketViewAction(RetrieveAPIView):
    authentication_classes = [JWTAuthentication]
    queryset = Ticket.objects.all()
    serializer_class = TicketSerializer

    def perform_create(self, serializer):
        user = self.request.user
        print(user)
        if not user.is_authenticated:
            raise PermissionDenied("Authentication is required to view ticket.")
    
        ticket = serializer.save(created_by=user, user=user)
        Log.objects.create(
            user=user,  
            action='VIEW',
            ticket=ticket,
            description=f"Ticket '{ticket.title}' viewed by {ticket.created_by}",
        )
        return ticket

    def view(self, request, *args, **kwargs):
        response = super().view(request, *args, **kwargs)
        return Response(
            {
                'ticket': response.data,
                'message': 'Ticket viewed successfully and logged.'
            },
            status=status.HTTP_200_OK
        )

    # def post(self, request, pk):
    #     try:
    #         ticket = Ticket.objects.get(id=pk)
    #     except Ticket.DoesNotExist:
    #         return Response({"detail": "Ticket not found"}, status=status.HTTP_404_NOT_FOUND)

    #     ticket_log = Log.objects.create(
    #         action='VIEW',
    #         user=request.user,
    #         description=f"Ticket '{ticket.title}' viewed by {ticket.created_by}",
    #     )
    #     serializer = TicketSerializer(ticket_log)
    #     return Response(serializer.data, status=status.HTTP_201_CREATED)



class UpdateTicketAPIView(generics.UpdateAPIView):
    authentication_classes = [JWTAuthentication]
    queryset = Ticket.objects.all()
    serializer_class = TicketSerializer
    
    def perform_update(self, serializer):
        user = self.request.user
        ticket = self.get_object()
        print(user)
        print(ticket)
 
        # if ticket.created_by != user:
        #     print(ticket.created_by != user)
        #     raise PermissionDenied("You are not allowed to edit this ticket.")

        updated_ticket = serializer.save(updated_by=user, user=user)
        print(updated_ticket)
        Log.objects.update(
            user=user,
            action='UPDATE',
            ticket=ticket,
            description=f"Ticket '{updated_ticket.title}' updated by {user}",
        )
        return updated_ticket

    def update(self, request, *args, **kwargs):
        response = super().update(request, *args, **kwargs)
        return Response(
            {
                'ticket': response.data,
                'message': 'Ticket updated successfully and logged.'
            },
            status=status.HTTP_200_OK
        )


class DeleteTicketAPIView(generics.DestroyAPIView):
    authentication_classes = [JWTAuthentication]
    queryset = Ticket.objects.all()
    serializer_class = TicketSerializer 

    def perform_destroy(self, serializer):
        user = self.request.user
        ticket = self.get_object()
        print(ticket)
        ticket.deleted_by=user
        ticket.save()

        Log.objects.create(
            user=user,
            action='DELETE',
            ticket=ticket,
            description=f"Ticket '{ticket.title}' deleted by {user}"
        )
        ticket.delete()
        return ticket
    
    def delete(self, request, *args, **kwargs):
        response = super().delete(request, *args, **kwargs)
        return Response(
            {
                'ticket': response.data,
                'message': 'Ticket deleted successfully and logged.'
            },
            status=status.HTTP_204_NO_CONTENT
        )



class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        token['role'] = user.role
        return token


class RegisterAPIView(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        # print(serializer)
        if serializer.is_valid():   
            serializer.save()
            return Response(serializer.data)


class SignupAPIView(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        serializer = SignupSerializer(data=request.data)
        print(serializer)   
        if serializer.is_valid():
            print(serializer.data)
            print("validated data", serializer.validated_data)
            validated_data = serializer.validated_data
            user = User.objects.create_user(email=validated_data['email'],
                                        username=validated_data['username'],
                                        password=validated_data['password'],
                                        role=validated_data['role'])
         
            # print(user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


    

class LoginAPIView(APIView):
    permission_classes = [AllowAny]
    # authentication_classes = [BasicAuthentication]
    def post(self, request):
        email = request.data['email']
        password = request.data['password']

        user = User.objects.filter(email=email).first()
        print(user)
        if user is None:
            raise AuthenticationFailed('User not found')
            
        if user.check_password(password):
            raise AuthenticationFailed('Invalid password')
        
        serialized_user = UserSerializer(user).data

        access_token = generate_access_token(user)
        refresh_token = generate_refresh_token(user)
        response = Response()
        response.set_cookie(key='refreshtoken', value=refresh_token, httponly=True)
        response.data = {
          'access_token': access_token,
           'user': serialized_user,
        }
        return response



class ClientListAPIView(ListAPIView):
    """View for listing clients"""
    permission_classes = [IsC]
    
    # serializer_class = ClientSerializer
    # queryset = Client.objects.all()

    def get(self, request):
        users = User.objects.all()
        serializer = UserSerializer(users, many=True)
        print(serializer)
        return Response(serializer.data)


class ClientView(APIView):
    permission_classes = [IsClient]

    def get(self, request):
        content = {'message': 'client'}
        return Response(content)
    

class SupportStaffView(APIView):
    permission_classes = [IsSupportStaff]

    def get(self, request):
        return Response({"message":"support staff"}, status=status.HTTP_200_OK)


class AdminView(ListAPIView):
    permission_classes = [IsAdmin]

    def get(self, request):
        return Response({"message":"admin"}, status = status.HTTP_200_OK)


class ManagerView(APIView):
    permission_classes = [IsManager]

    def get(self, request):
        return Response({"message":"manager"}, status=status.HTTP_200_OK)
    

class ViewerView(APIView):
    permission_classes = [IsViewer]

    def get(self, request):
        return Response({"message":"viewer"}, status=status.HTTP_200_OK)


class Home(APIView):
    authentication_classes = [JWTAuthentication]

    def get(self, request):
        content = {'message': 'Hello, World!'}
        return Response(content)
    

# class LoginAPIView(APIView):
#     def post(self, request):
#         serializer = LoginSerializer(data=request.data)
#         print(serializer)
#         if serializer.is_valid():
#                 print(serializer.validated_data)
#                 email = serializer.validated_data.get('email')
#                 password = serializer.validated_data.get('password')
#                 print("email", email)
#                 print("pass", password)
#                 user = authenticate(username=email, password=password)
#                 print(user)
        
#                 if user:
#                     return Response({
#                     "message": "Login successful"
#                     }, status=status.HTTP_200_OK)
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



class UserView(APIView):
    def get(self, request):
        token = request.COOKIES.get('jwt')
        if not token:
            raise AuthenticationFailed("Unauthenticated!")
        try:
            payload = jwt.decode(token, 'secret', algorithms="HS256")

        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed("Unauthenticated!")
        user = User.objects.filter(id=payload['id']).first()
        serializer = UserSerializer(user)
        return Response(serializer.data)
    





class SessionView(APIView):
    authentication_classes = [SessionAuthentication, BasicAuthentication]
    permission_classes = [IsAuthenticated]

    @staticmethod
    def get(request, format=None):
        return JsonResponse({'isAuthenticated':True})



# class ClientView(APIView):
#     permission_classes = [IsAuthenticated|IsClient]

#     def get(self, request):
#         return Response({"message":"client"}, status=status.HTTP_200_OK)







class ClientTicketListAPIView(ListAPIView):
    """View for listing tickets"""
    permission_classes = [IsClient]
    serializer_class = TicketSerializer
    
    def get_queryset(self):
        user = self.request.user 
        return Ticket.objects.filter(user=user)


class ViewerTicketListAPIView(ListAPIView):
    """View for listing tickets"""
    permission_classes = [IsViewer]
    serializer_class = TicketSerializer
    
    def get_queryset(self):
        user = self.request.user 
        return Ticket.objects.filter(user=user)


class StaffTicketListAPIView(ListAPIView):
    """views for listing tickets"""
    permission_classes = [IsSupportStaff]
    serializer_class = TicketSerializer
    
    def get_queryset(self):
        user = self.request.user 
        return Ticket.objects.filter(user=user)


class MangerTicketListAPIView(ListAPIView):
    """View for listing tickets"""
    permission_classes = [IsManager]
    serializer_class = TicketSerializer

    def get_queryset(self):
        """
        Manager can view tickets assigned to clients, staff, or viewers.
        Manager cannot view admin tickets.
        """
        user = self.request.user
        # Check if the user is a manager
        if user.role == 'manager':
            # Return tickets assigned to clients, staff, viewers, or the manager themselves, excluding admin tickets
            return Ticket.objects.exclude(
                user__role='admin'  # Exclude tickets assigned to Admins
            )
        return Ticket.objects.none()
    

       


# logger = logging.getLogger(__name__)

# class TicketCreateAPIView(CreateAPIView):
#     permission_classes=[AllowAny]
#     queryset = Ticket.objects.all()
#     serializer_class = TicketSerializer

#     def perform_create(self, serializer):
#         user = self.request.user
#         ticket = serializer.save(created_by=user, created_at=timezone.now())
#         logger.info(f"Ticket created by {user.username} at {timezone.now()}")
#         logger.info(f"Ticket ID {ticket.id} created successfully.")



class TicketListAPIView(ListAPIView):
    """View for listing tickets"""
    permission_classes = [IsAdmin]

    queryset = Ticket.objects.all()
    serializer_class = TicketSerializer
    


class TicketCreateAPIView(CreateAPIView):
    """Create tickets"""
    permission_classes = [AllowAny]
    # permission_classes = [IsAdmin | IsManager | IsClient]

    queryset = Ticket.objects.all()
    serializer_class = TicketSerializer


class TicketRetrieveAPIView(RetrieveAPIView):
    """Retrieve ticket"""
    permission_classes = [IsViewer | IsAdmin]

    queryset = Ticket.objects.all()
    serializer_class = TicketSerializer


class TicketUpdateAPIView(UpdateAPIView):
    '''update ticket'''
    permission_classes = [IsAdmin]

    queryset = Ticket.objects.all()
    serializer_class = TicketSerializer


class TicketDestroyAPIView(DestroyAPIView):
    '''destroy ticket'''
    permission_classes = [IsAdmin]

    queryset= Ticket.objects.all()
    serializer_class=TicketSerializer



# class TicketsList(ListAPIView):
#     permission_classes = [IsViewer]

#     def get(self, request):
#         tickets = Ticket.objects.all()
#         serializer = TicketSerializer(tickets, many=True)
#         return Response(serializer.data)


# class TicketCreateAPIView(CreateAPIView):
#     """Create tickets"""
#     permission_classes = [IsClient|IsManager|IsAdmin]
    
#     def post(self, request):
#         serializer = TicketSerializer(data=request.data)
#         if serializer.is_valid():
#             serializer.save()
#             return Response(serializer.data,
#                            status=status.HTTP_201_CREATED)
#         return Response(serializer.errors, 
#                        status=status.HTTP_400_BAD_REQUEST)



# class TicketRetrieveAPIView(RetrieveAPIView):
#     """Retrieve ticket"""
#     permission_classes = [IsAdmin]
#     serializer_class = TicketSerializer
#     queryset = Ticket.objects.get(id=pk)

    # def get(self, request, pk):
    #     ticket = Ticket.objects.get(id=pk)
    #     serializer = TicketSerializer(ticket)
    #     return Response(serializer.data)
    

# class TicketUpdateAPIView(UpdateAPIView):
#     """Update tickets"""
#     permission_classes = [IsSupportStaff|IsAdmin]

#     def put(self, request, pk):
#         ticket = Ticket.objects.get(id=pk)
#         serializer = TicketSerializer(ticket, data=request.data)
#         if serializer.is_valid():
#             serializer.save()
#             return Response(serializer.data)
#         return Response(serializer.errors, 
#                        status=status.HTTP_400_BAD_REQUEST)
    

# class TicketDestroyAPIView(DestroyAPIView):
#     """Destroy ticket"""
#     permission_classes = [IsAdmin]

#     def delete(self, request, pk):
#         ticket = Ticket.objects.get(id=pk)
#         ticket.delete()
#         return Response(status=status.HTTP_204_NO_CONTENT)







# from django.http import Http404
# from rest_framework.permissions import BasePermission
# from rest_framework.views import APIView


# class TicketList(APIView):
#     permission_classes = [IsAdmin|IsViewer]

#     def get(self, request):
#         tickets = Ticket.objects.all()
#         serializer = TicketSerializer(tickets, many=True)
#         return Response(serializer.data)
    

# class TicketCreate(APIView):
#     permission_classes = [IsClient|IsManager]

#     def post(self,request):
#         serializer = TicketSerializer(data=request.data)
#         if serializer.is_valid():
#             serializer.save()
#             return Response(serializer.data, status=status.HTTP_201_CREATED)
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    


# class TicketDetail(APIView):
#     permission_classes = [IsAdmin]

#     def get_object(self, pk):
#         try:
#             return Ticket.objects.get(pk=pk)
#         except Ticket.DoesNotExist:
#             raise Http404
        
#     def get(self, *args, **kwargs):
#         pk = kwargs.get('pk')
#         ticket = self.get_object(pk)
#         serializer = TicketSerializer(ticket)
#         return Response(serializer.data)
    
#     permission_classes = [IsSupportStaff]
    
#     def put(self, request, *args, **kwargs):
#         pk = kwargs.get('pk')
#         ticket = self.get_object(pk)
#         serializer = TicketSerializer(ticket, data=request.data)
#         if serializer.is_valid():
#             serializer.save()
#             return Response(serializer.data)
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
#     def delete(self, *args, **kwargs):
#         pk = kwargs.get('pk')
#         ticket = self.get_object(pk)
#         ticket.delete()
#         return Response(status=status.HTTP_204_NO_CONTENT)
    
    



