from django.urls import path
from drf_api import views


urlpatterns = [
    path('user/register/',views.RegisterUser.as_view() ),
    path('user/login/',views.LoginUser.as_view() ),
    path('book/get_all/',views.BookOperation.as_view() ),
    path('book/get/<int:pk>',views.BookOperation.as_view() ),
    path('book/add/',views.BookOperation.as_view() ),
    path('book/update/<int:pk>',views.BookOperation.as_view() ),
    path('book/delete/<int:pk>',views.BookOperation.as_view() ),
    path('book/return/<int:pk>',views.BookReturn.as_view() ),
    path('book/borrow/<int:pk>',views.BookBorrow.as_view() ),
    path('member/delete/<int:pk>',views.MemberDelete.as_view() ),

]
