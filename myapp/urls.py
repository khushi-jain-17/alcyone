from django.urls import path
from myapp import views
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView, TokenVerifyView



urlpatterns = [
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/token/verify/', TokenVerifyView.as_view(), name='token_verify'),
    # path('token/', views.CustomTokenObtainPairView.as_view(), name='token_obtain'),

    path('viewer-tickets/', views.ViewerTicketListAPIView.as_view()),
    path('client-tickets/', views.ClientTicketListAPIView.as_view()),
    path('staff-tickets/', views.StaffTicketListAPIView.as_view()),
    path('manager-tickets/', views.MangerTicketListAPIView.as_view()),

    path('tickets/', views.TicketListAPIView.as_view()),
    path('ticket/<int:pk>/', views.TicketRetrieveAPIView.as_view()),
    path('ticket-update/<int:pk>/', views.TicketUpdateAPIView.as_view()),
    path('ticket-create/', views.TicketCreateAPIView.as_view()),
    path('ticket-delete/<int:pk>/', views.TicketDestroyAPIView.as_view()),

    path('register/', views.RegisterAPIView.as_view()),
    path('signup/', views.SignupAPIView.as_view(), name='signup'),
    path('login/', views.LoginAPIView.as_view()),

    path('api/', views.AdminView.as_view()),
    path('manager/', views.ManagerView.as_view()),
    path('client/', views.ClientView.as_view()),
    path('viewer/', views.ViewerView.as_view()),
    path('staff/', views.SupportStaffView.as_view()),

    path('', views.Home.as_view()),

    path('clients/', views.ClientListAPIView.as_view()),
    path('create-ticket/', views.CreateTicketAPIView.as_view()),
    path('update-ticket/<int:pk>/', views.UpdateTicketAPIView.as_view()),
    path('delete-ticket/<int:pk>/', views.DeleteTicketAPIView.as_view()),
    path('view/<int:pk>/', views.TicketViewAction.as_view()),

]

