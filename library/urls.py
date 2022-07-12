from django.contrib import admin
from django.urls import path,include
from rest_framework_simplejwt.views import TokenObtainPairView,TokenRefreshView,TokenVerifyView
import drf_api


urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('drf_api.urls')),
#     path('gettoken/',TokenObtainPairView.as_view(),name='token_obtain_pair'),
#     path('refreshtoken/',TokenRefreshView.as_view(),name='token_refresh'),
#     path('verifytoken/',TokenVerifyView.as_view(),name='token_verify')
]
