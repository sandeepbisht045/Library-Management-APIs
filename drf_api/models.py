from django.db import models

# Create your models here.
class User(models.Model):
    username=models.CharField(default="",max_length=50)
    password=models.CharField(max_length=1000)
    is_librarian=models.IntegerField(default=0)
    

    def __str__(self):
        return self.username


class Book(models.Model):
    name=models.CharField(default="",max_length=200)
    author=models.CharField(default="",max_length=50)
    status=models.CharField(max_length=10,default="available")
    user=models.ForeignKey(User,on_delete=models.SET_NULL, null = True,blank=True)
    def __str__(self):
        return self.name
