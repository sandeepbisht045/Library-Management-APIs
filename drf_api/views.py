########################################## Project Import ######################################################################

from rest_framework.views import APIView
from rest_framework import status
from rest_framework.response import Response
from library.settings import SECRET_KEY
from .serializers import UserSerializer,UserLoginSerializer,BookOperationSerializer
from . models import User,Book
from django.contrib.auth.hashers import make_password, check_password
import jwt
from library.utils.jwt_token import get_tokens_for_user,validate_token
from decouple import config
# import decode


########################################## Project Import ######################################################################

# Create your views here.

class RegisterUser(APIView):
    def post(self,request,format=None):
        serializer=UserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.validated_data['password']=make_password(serializer.validated_data['password'])
            serializer.save()
            return Response({"message":'User Registeres Successfully'},status=status.HTTP_201_CREATED)
        return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)
   
   
class LoginUser(APIView):
    def post(self,request,format=None):
        serializer=UserLoginSerializer(data=request.data)
        if serializer.is_valid():
            username=serializer.data.get('username')
            password=serializer.data.get('password')
            user_data = User.objects.get(username=username)
            user = check_password(password, user_data.password)
            
            if user:
                token=get_tokens_for_user(user_data )
                decodeJTW = jwt.decode(token['access'], SECRET_KEY, algorithms=["HS256"]);
                decodeJTW['is_librarian'] = user_data.is_librarian
                encoded_access_token = jwt.encode(decodeJTW, SECRET_KEY, algorithm="HS256").decode('utf-8')

                return Response({'token':str(encoded_access_token),"message":'User Login Success'},status=status.HTTP_200_OK)
            return Response({"message":'Invalid Credentials'},status=status.HTTP_401_UNAUTHORIZED)

        return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)

class BookOperation(APIView):
 
    def get(self,request,pk=None,format=None):
       
        if pk is not None:
            try:
              book=Book.objects.get(id=pk)
            except:
              return Response({"message":"id is invalid"},status=status.HTTP_400_BAD_REQUEST)

            serializer=BookOperationSerializer(book)
            return Response({"data":serializer.data},status=status.HTTP_200_OK)
            
        query=Book.objects.all()
        serializer=BookOperationSerializer(query,many=True)
        return Response({"data":serializer.data},status=status.HTTP_200_OK)

# add books in system by librarian
    def post(self,request,format=None):
        header_=request.META['HTTP_AUTHORIZATION'].split(" ")  
        status_,message,data_=validate_token(header_[1],librarian=True)
        if not status_ and not message:
            return Response({"message":"no permission to add"})
        if not status_:
            return Response({"message":'Token Authentication failed'},status=status.HTTP_401_UNAUTHORIZED)
        serializer=BookOperationSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message":'Book added Successfully'},status=status.HTTP_201_CREATED)
        return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)

        

# update books in system by librarian
    def put(self,request,pk=None,format=None):
        header_=request.META['HTTP_AUTHORIZATION'].split(" ")  
        status_,message,data_=validate_token(header_[1],librarian=True)
        if not status_ and not message:
            return Response({"message":"no permission to update data"})
        if not status_:
            return Response({"message":'Token Authentication failed'},status=status.HTTP_401_UNAUTHORIZED)
        query=Book.objects.filter(id=pk).first()
        if query is None:
            return Response({"message":"book id is invalid"},status=status.HTTP_400_BAD_REQUEST)

        serializer=BookOperationSerializer(query,data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message":'Book updated Successfully'},status=status.HTTP_200_OK)
        return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)

# delete book in system by librarian
    def delete(self,request,pk=None,format=None):
        header_=request.META['HTTP_AUTHORIZATION'].split(" ")  
        status_,message,data_=validate_token(header_[1],librarian=True)
        if not status_ and not message:
            return Response({"message":"no permission to delete data"})
        if not status_:
            return Response({"message":'Token Authentication failed'},status=status.HTTP_401_UNAUTHORIZED)
        query=Book.objects.filter(id=pk).first()
        if query is None:
            return Response({"message":"book id is invalid"},status=status.HTTP_400_BAD_REQUEST)
        query.delete()
        return Response({"message":'Book removed successfully'},status=status.HTTP_200_OK)


# add books in system by librarian
    def post(self,request,format=None):
        header_=request.META['HTTP_AUTHORIZATION'].split(" ")  
        status_,message,data_=validate_token(header_[1],librarian=True)
        if not status_ and not message:
            return Response({"message":"no permission to add"})
        if not status_:
            return Response({"message":'Token Authentication failed'},status=status.HTTP_401_UNAUTHORIZED)
        serializer=BookOperationSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message":'Book added Successfully'},status=status.HTTP_201_CREATED)
        return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)

# borrow book by member
class BookBorrow(APIView):
    def get(self,request,pk=None,format=None):
        header_=request.META['HTTP_AUTHORIZATION'].split(" ")  
        status_,message,data_=validate_token(header_[1])
        if not status_ and  message=="m":
            return Response({"message":"not authorized to borrow"})
        if not status_:
            return Response({"message":'Token Authentication failed'},status=status.HTTP_401_UNAUTHORIZED)
 
        try:
            book=Book.objects.get(id=pk)
        except:
            return Response({"message":"id is invalid"},status=status.HTTP_400_BAD_REQUEST)
        if book.status=="borrowed":
            return Response({"message":"book is already borrowed"},status=status.HTTP_404_NOT_FOUND)
        book.status='borrowed'
        book.user=User.objects.get(id=data_)
        book.save()
        return Response({"message":"book has been assigned to you"},status=status.HTTP_200_OK)
       
    #    return book as a member
class BookReturn(APIView):
    def get(self,request,pk=None,format=None):
        header_=request.META['HTTP_AUTHORIZATION'].split(" ")  
        status_,message,data_=validate_token(header_[1])
        if not status_ and  message=="m":
            return Response({"message":"not authorized to return or borrow"})
        if not status_:
            return Response({"message":'Token Authentication failed'},status=status.HTTP_401_UNAUTHORIZED)
 
        try:
            book=Book.objects.get(id=pk)
        except:
            return Response({"message":"id is invalid"},status=status.HTTP_400_BAD_REQUEST)
        if book.status=="available":
            return Response({"message":"book is already been returned"},status=status.HTTP_404_NOT_FOUND)
        book.status='available'
        book.user=None
        book.save()
        return Response({"message":"book has been returned successfully"},status=status.HTTP_200_OK)

# member deleting his own account
class MemberDelete(APIView):
    def delete(self,request,pk=None,format=None):
        header_=request.META['HTTP_AUTHORIZATION'].split(" ")  
        status_,message,data_=validate_token(header_[1])
        if not status_ and  message=="m":
            return Response({"message":"not authorized to return or borrow"})
        if not status_:
            return Response({"message":'Token Authentication failed'},status=status.HTTP_401_UNAUTHORIZED)
 
        query=Book.objects.filter(user__in=User.objects.filter(id=data_))
        if query:
            return Response({"message":"return books first"},status=status.HTTP_404_NOT_FOUND)
        del_=User.objects.get(id=data_)
        del_.delete()
        return Response({"message":"member has been deleted successfully"},status=status.HTTP_200_OK)