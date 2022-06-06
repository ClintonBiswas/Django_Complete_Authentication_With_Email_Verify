from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import path
from user import views
urlpatterns = [
    path('admin/', admin.site.urls),
    path('', views.Home, name='home'),
    path('register/', views.RegisterView.as_view(), name='register'),
    path('login/', views.LoginView.as_view(), name='login'),
    path('logout/', views.LogoutView.as_view(), name='logout'),
    path('activate/<uidb64>/<token>/', views.AccountActivate.as_view(), name='activate'),
    path('set-new-password/<uidb64>/<token>/', views.ResetUserPasswordView.as_view(), name='set-new-password'),
    path('reset-password/', views.ResetPasswordView.as_view(), name='reset-password'),
]
urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)