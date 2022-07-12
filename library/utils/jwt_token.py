from rest_framework_simplejwt.tokens import  RefreshToken
from drf_api.models import User
import jwt
from library.settings import SECRET_KEY


def get_tokens_for_user(user):
    refresh=RefreshToken.for_user(user)
    access_token=refresh.access_token
    return {'refresh':str(refresh),'access':str(access_token)}

def validate_token(token_,librarian=False):
    access=token_
    if not access:
        return False,"token not provided",""
    try:
        decode_access = jwt.decode(access, SECRET_KEY, algorithms=["HS256"]);
        user_id=decode_access.get("user_id")
    except:
        return False,"token expired",""
    if librarian:
        query=User.objects.filter(id=user_id,is_librarian=1)
        if query:
            return True,"",user_id
        else:
            return False,"",""
            
    if not librarian:
        query=User.objects.filter(id=user_id,is_librarian=0)
        if query:
            return True,"m",user_id
        else:
            return False,"m",""
    if not  User.objects.get(id=user_id):
        return False ,"no user exist",""
    
    return True,"authenticated",user_id
