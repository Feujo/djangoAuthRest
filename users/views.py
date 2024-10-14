from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.exceptions import AuthenticationFailed

from .serializers import UserSerializer
from .models import User
import jwt, datetime
# Create your views here.

class RegisterView(APIView):
    
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data, status=201)
    
class LoginView(APIView):
    def post(self, request):
        email =  request.data['email']
        password= request.data['password']
        
        user = User.objects.filter(email = email).first()
        
        if user is None : 
            raise AuthenticationFailed('User not found!')
        if not user.check_password(password):
            raise AuthenticationFailed('incorrect password')
        payload = {
            'id': user.id,
            'exp': datetime.datetime.now() + datetime.timedelta(minutes = 60),
            'iat': datetime.datetime.now()
        }
        
        token = jwt.encode(payload, 'secret', algorithm='HS256')
        
        response = Response()
        
        response.set_cookie(key='jwt', value = token, httponly = True)
        
        response.data = {
            'jwt': token
        }
        return response

class UserView(APIView):
    
    def get(self, request):
        token = request.COOKIES.get('jwt')
        
        if not token:
            raise AuthenticationFailed('Unauthentication')
        
        try:
            payload = jwt.decode(token, 'secret', algorithms=['HS256'])
        
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('Unauthentification')
        
        user = User.objects.filter(id = payload['id']).first()
        serializer = UserSerializer(user)
        
        return Response(serializer.data)

class LogoutView(APIView):
    
    def post(self, request):
        response = Response()
        response.delete_cookie('jwt')
        response.data = {
            'message' : 'success'
        }
        
        return response