import json

from django.views import View
from django.contrib.auth import authenticate
from rest_framework.authtoken.models import Token

from django.http import HttpResponse


class Login(View):

    def post(self, request, *args, **kwargs):
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(username=username, password=password)

        if user:
            token = Token.objects.create(user=user)
            return HttpResponse(json.dumps({'token': token}))
        else:
            return HttpResponse(json.dumps({'error': "Error occured"}), status=400)
