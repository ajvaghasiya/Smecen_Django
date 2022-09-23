from django.contrib import admin
from .models import User, SocialUserToken, Country, State

admin.site.register(User)
admin.site.register(SocialUserToken)
admin.site.register(Country)
admin.site.register(State)
