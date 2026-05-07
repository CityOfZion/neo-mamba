from neo3.sc.compiletime import public
from neo3.sc.contracts.rolemanagement import RoleManagement


@public
def get_role(role: int, index: int) -> list:
    return RoleManagement.get_designated_by_role(role, index)
