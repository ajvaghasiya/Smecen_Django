from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils.translation import ugettext_lazy as _


# User Model
class User(AbstractUser):
    username = models.CharField(max_length=30, unique=False)
    email = models.EmailField(
        _('email address'), max_length=254, unique=True, null=True, blank=True)
    company_name = models.CharField(max_length=255, null=True, blank=True)
    middle_name = models.CharField(max_length=30, null=True, blank=True)
    street_address = models.CharField(max_length=60, null=True, blank=True)
    street_address2 = models.CharField(max_length=60, null=True, blank=True)
    city = models.CharField(max_length=30, null=True, blank=True)
    state = models.CharField(max_length=30, null=True, blank=True)
    zip = models.CharField(max_length=30, null=True, blank=True)
    country = models.CharField(default="select Country", max_length=50)
    telephone_number = models.CharField(max_length=30, null=True, blank=True)
    sms = models.BooleanField(default=True)

    class Meta(AbstractUser.Meta):
        swappable = 'AUTH_USER_MODEL'

# Social User Token Model
class SocialUserToken(models.Model):

    token = models.TextField(blank=False, null=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE)

    def __str__(self):
        return self.user.first_name + " - " + self.user.last_name
    
    
class Country(models.Model):
    country = models.CharField(max_length=50, null=True, blank=True)
    sortname = models.CharField(max_length=20, null = True, blank=True)
    phoneCode = models.CharField(max_length=30, null=True, blank=True)
    
    def __str__(self):
        return self.country
    
class State(models.Model):
    state = models.CharField(max_length=50,null=True, blank=True)
    country = models.ForeignKey(Country, on_delete=models.CASCADE)
    
        
    def __str__(self):
        return self.state
    
    
    
