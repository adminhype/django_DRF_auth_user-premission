from rest_framework.permissions import BasePermission, SAFE_METHODS


class IsStaffOrReadOnly(BasePermission):
    def has_permission(self, request, view):
        is_staff = bool(request.user and request.user.is_staff)
        return is_staff or request.method in SAFE_METHODS


class IsGroupMember(BasePermission):
    def has_permission(self, request, view):
        return request.user.groups.filter(name="Manager").exists()


class BlockSpecificUser(BasePermission):
    def has_permission(self, request, view):
        blocked_user = ["böser_kevin"]
        return request.user.username not in blocked_user


# has object permissions

class isAdminForDeleteOrPatchAndReadOnly(BasePermission):
    def has_object_permission(self, request, view, obj):
        if request.method in SAFE_METHODS:
            return True
        elif request.method == "DELETE":
            return bool(request.user and request.user.is_superuser)
        else:
            return bool(request.user and request.user.is_staff)


class isOwnerOrAdmin(BasePermission):
    def has_object_permission(self, request, view, obj):
        if request.method in SAFE_METHODS:
            return True
        elif request.method == "DELETE":
            return bool(request.user and request.user.is_superuser)
        else:
            return bool(request.user and request.user == obj.user)

# class IsOwnerOrAdmin(BasePermission):
#     def has_object_permission(self, request, view, obj):
#         if request.method in SAFE_METHODS:
#             return True
#         return obj.user == request.user or request.user.is_superuser
