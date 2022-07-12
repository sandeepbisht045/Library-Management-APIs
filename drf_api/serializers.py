from pyexpat import model
from rest_framework import serializers
from .models import User,Book

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model=User
        fields=['id','username','password','is_librarian']

    def validate(self,data):
        username=data.get('username')
        if not username.isalnum() or len(username.strip())<=6:
            raise serializers.ValidationError('username must contain only alphanumeric with minimum 7 characters')
        
        if User.objects.filter(username=username):
            raise serializers.ValidationError('user already registered')

        user_type=[0,1]
        if int(data.get('is_librarian')) not in user_type:
            raise serializers.ValidationError('is_librarian field should be 0 or 1')
        password=data.get('password')
        if len(password.strip())<=6:
            raise serializers.ValidationError('password must contain atleat 7 characters')
        return data

class UserLoginSerializer(serializers.ModelSerializer):
    class Meta:
        model=User
        fields=['username','password']
    

class BookOperationSerializer(serializers.ModelSerializer):
    class Meta:
        model=Book
        fields=['name','author','status','id']

    def validate(self,data):
        lst=["available","borrowed"]
        if data.get('status') not in lst:
            print(data,"hh")
            raise serializers.ValidationError('status must be available or borrowed')
        return data


    
    

