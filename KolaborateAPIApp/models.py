from django.db import models
from django.contrib.auth.models import User

# Create your models here.
AUTH_PROVIDER = {'Email':'Email', 'Google':'Google'}

class IndividualProfile(models.Model):
    Email = 'Email'
    Google = 'Google'

    STATUS_CHOICES = [
        (Email, 'Email'),
        (Google, 'Google'),
    ]
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    contact = models.CharField(max_length=255, null=True, blank=True)
    date_of_birth = models.DateField(null=True, blank=True)
    activation_code = models.PositiveBigIntegerField(null=True, blank=True)
    auth_provider = models.CharField(max_length=10, choices=STATUS_CHOICES, default=Email)
    # role = models.ForeignKey(Role, on_delete=models.CASCADE, default=1, related_name='individual_profiles')  # ForeignKey for a single role

    def __str__(self):
        return str(self.user.email)