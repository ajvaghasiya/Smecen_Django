from django.db import models


# Create your models here.


class Contact(models.Model):
    name = models.CharField(max_length=30, null=True, blank=True)
    email_id = models.EmailField(max_length=254, null=True, blank=True)
    message = models.CharField(max_length=150, null=True, blank=True)

    def __str__(self):
        return self.name
