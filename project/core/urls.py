from django.urls import path
from . views import *
from rest_framework.routers import DefaultRouter
from . views import *

# router = DefaultRouter()
# router.register(r'create-room/',CreateRoomViewSet)

urlpatterns = [

    path('register/', UserRegistrationView.as_view(), name="register"),
    path('login/', UserLoginView.as_view(), name="login"),
    path('user/profile/', UserProfileView.as_view(), name="profile"),
    path('user/change-password/', UserChangePasswordView.as_view(), name="change_password"),
    path('user/send-reset-password-email/', SendPasswordResetEmailView.as_view(), name="send_reset_password_email"),
    path('user/reset-password/<uid>/<token>/', UserPasswordResetView.as_view(), name='reset-password'),
    path('create-room/',CreateRoomList.as_view(),name='create_room'),
    path('delete-rooms/',DeleteRoomView),
    path('user/profile-detail/<str:email>/',ProfileView.as_view()),
    
    
    
]