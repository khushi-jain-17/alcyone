from rest_framework import serializers
from .models import User, Client, Ticket
from datetime import datetime
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from django.contrib.auth.hashers import make_password
from django.contrib.auth import get_user_model


class SignupSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=100)
    email = serializers.EmailField(max_length=100)
    password = serializers.CharField(write_only=True)
    role = serializers.CharField(max_length=30)

    def create(self, validated_data):
        user = User.objects.create_user(email=validated_data['email'],
                                        username=validated_data['username'],
                                        password=validated_data['password'],
                                        role=validated_data['role'])
        return user

    # class Meta:
    #     model = User
    #     fields = ('username', 'email', 'password','role')

        # def create(self, validated_data):
    #     print("validated data", **validated_data)
    #     user = User.objects.create(**validated_data)
    #     return user


class LoginSerializer(serializers.Serializer):
    email = serializers.CharField(max_length=100)
    password = serializers.CharField(write_only=True)

    # def validate(self, data):
    #     user = authenticate(email=data['email'], password=data['password'])
    #     if not user:
    #         raise serializers.ValidationError('Invalid email or password')
    #     return user



class TicketSerializer(serializers.Serializer):        
    title = serializers.CharField(max_length=100)
    description = serializers.CharField(max_length=200)
    status = serializers.CharField(max_length=200)
    created_by = serializers.CharField(max_length=100, required=False)
    updated_at = serializers.CharField(max_length=100, required=False)
    deleted_by = serializers.CharField(max_length=100, required=False)
    # assigned_to = UserSerializer()

    User = get_user_model()
    user = serializers.PrimaryKeyRelatedField(queryset=User.objects.all(), required=False)

    class Meta:
        model = Ticket
        fields = ['title','description','status','created_by','assigned_to','created_at', 'user', 'updated_at','deleted_by']

#     def validate_title(self, value):
#         """
#         Check that the blog post is about Django.
#         """
#         if 'django' not in value.lower():
#             raise serializers.ValidationError("Blog post is not about Django")
#         return value
        
    def create(self, validated_data):
        print(validated_data)
        ticket = Ticket.objects.create(**validated_data)
        return ticket 
    
    def update(self, instance, validated_data):
        instance.title = validated_data.get('title', instance.title)
        instance.description = validated_data.get('description', instance.description)
        instance.status = validated_data.get('status', instance.status)
        instance.created_by = validated_data.get('created_by', instance.created_by)
#         instance.assigned_to = validated_data.get('assigned_to', instance.assigned_to)
        instance.created_at = validated_data.get('created_at', instance.created_at)
        instance.save()
        return instance 
    
    def delete(self, validated_data):
        ticket = Ticket.objects.delete(**validated_data)

    def view(self, validated_data, pk):
        ticket = Ticket.objects.get(id=pk)    
        # ticket = Ticket.objects.get(**validated_data)    



class UserSerializer(serializers.ModelSerializer):
    username = serializers.CharField(max_length=100)
    email = serializers.EmailField(max_length=100)
    password = serializers.CharField(write_only=True)
    role = serializers.CharField(max_length=30)
    tickets = TicketSerializer(many=True, read_only=True)

    class Meta:
        model = User
        fields = ['username', 'email', 'password', 'role', 'tickets' ]

    def create(self, validated_data):
        user = User.objects.create(
            email=validated_data['email'],
            username=validated_data['username'],
            password=make_password(validated_data['password']),
            role=validated_data['role'] )
        return user
      
        # password = validated_data.pop('password', None)
        # instance = self.Meta.model(**validated_data) #doesnt include password

        # if password is not None:
        #     instance.set_password(password) #hashes password
        # instance.save()
        # return instance    


# class SignupSerializer(serializers.Serializer):
#     username = serializers.CharField(max_length=100)
#     email = serializers.EmailField(max_length=100)
#     password = serializers.CharField(max_length=100)

#     def create(self, validated_data):
#         user = User.objects.create(**validated_data)
#         return user    



    


class ClientSerializer(serializers.ModelSerializer):
    class Meta:
        model=Client
        fields=['user']
    
    



