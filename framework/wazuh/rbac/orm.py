# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import logging
import os
import re
from datetime import datetime
from enum import IntEnum, Enum
from functools import partial
from shutil import chown
from time import time
from typing import Union

import yaml
from sqlalchemy import create_engine, UniqueConstraint, Column, DateTime, String, Integer, ForeignKey, Boolean, or_, \
    CheckConstraint
from sqlalchemy import desc
from sqlalchemy.dialects.sqlite import TEXT
from sqlalchemy.event import listens_for
from sqlalchemy.exc import IntegrityError, InvalidRequestError, OperationalError
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy.orm.exc import UnmappedInstanceError
from werkzeug.security import check_password_hash, generate_password_hash

from api.configuration import security_conf
from api.constants import SECURITY_PATH
from wazuh.core.common import wazuh_uid, wazuh_gid, get_api_revision
from wazuh.core.utils import get_utc_now, safe_move
from wazuh.rbac.utils import clear_cache

# Max reserved ID value
max_id_reserved = 99
cloud_reserved_range = 89

# Start a session and set the default security elements
_db_file = os.path.join(SECURITY_PATH, "rbac.db")
_db_file_tmp = f"{_db_file}.tmp"
_engine = create_engine(f"sqlite:///{_db_file}", echo=False)
_Base = declarative_base()
_Session = sessionmaker(bind=_engine)
_new_columns = {"resource_type"}

# Required rules for role
# Key: Role - Value: Rules
required_rules_for_role = {1: [1, 2]}
required_rules = {required_rule for r in required_rules_for_role.values() for required_rule in r}


class ResourceType(Enum):
    USER = 'user'
    PROTECTED = 'protected'
    DEFAULT = 'default'


# Error codes for Roles and Policies managers
class SecurityError(IntEnum):
    # The element already exist in the database
    ALREADY_EXIST = 0
    # The element is invalid, missing format or property
    INVALID = -1
    # The role does not exist in the database
    ROLE_NOT_EXIST = -2
    # The policy does not exist in the database
    POLICY_NOT_EXIST = -3
    # Admin resources of the system
    ADMIN_RESOURCES = -4
    # The role does not exist in the database
    USER_NOT_EXIST = -5
    # The token-rule does not exist in the database
    TOKEN_RULE_NOT_EXIST = -6
    # The rule does not exist in the database
    RULE_NOT_EXIST = -7
    # The relationships can not be removed
    RELATIONSHIP_ERROR = -8
    # Protected resources
    PROTECTED_RESOURCES = -9
    # Database constraint error
    CONSTRAINT_ERROR = -10


def json_validator(data):
    """Function that returns True if the provided data is a valid dict, otherwise it will return False

    Parameters
    ----------
    data : dict
        Data that we want to check

    Returns
    -------
    True -> Valid dict | False -> Not a dict or invalid dict
    """
    return isinstance(data, dict)


@listens_for(_Session, 'after_flush')
def delete_orphans(session, instances):
    if session.deleted:
        query = session.query(UserRoles).filter(or_(UserRoles.user_id.is_(None), UserRoles.role_id.is_(None))).all()
        query.extend(session.query(RolesRules).filter(or_(RolesRules.role_id.is_(None),
                                                          RolesRules.rule_id.is_(None))).all())
        query.extend(session.query(RolesPolicies).filter(or_(RolesPolicies.role_id.is_(None),
                                                             RolesPolicies.policy_id.is_(None))).all())
        for orphan in query:
            session.delete(orphan)


class RolesRules(_Base):
    """
    Relational table between Roles and Policies, in this table are stored the relationship between the both entities
    The information stored from Roles and Policies are:
        id: ID of the relationship
        role_id: ID of the role
        policy_id: ID of the policy
        level: Priority in case of multiples policies, higher = more priority
        created_at: Date of the relationship creation
    """
    __tablename__ = "roles_rules"

    # Schema, Many-To-Many relationship
    id = Column('id', Integer, primary_key=True)
    role_id = Column('role_id', Integer, ForeignKey("roles.id", ondelete='CASCADE'))
    rule_id = Column('rule_id', Integer, ForeignKey("rules.id", ondelete='CASCADE'))
    created_at = Column('created_at', DateTime, default=get_utc_now())
    __table_args__ = (UniqueConstraint('role_id', 'rule_id', name='role_rule'),
                      )

    roles = relationship("Roles", backref="rules_associations")
    rules = relationship("Rules", backref="roles_associations")


# Declare relational tables
class RolesPolicies(_Base):
    """
    Relational table between Roles and Policies, in this table are stored the relationship between the both entities
    The information stored from Roles and Policies are:
        id: ID of the relationship
        role_id: ID of the role
        policy_id: ID of the policy
        level: Priority in case of multiples policies, higher = more priority
        created_at: Date of the relationship creation
    """
    __tablename__ = "roles_policies"

    # Schema, Many-To-Many relationship
    id = Column('id', Integer, primary_key=True)
    role_id = Column('role_id', Integer, ForeignKey("roles.id", ondelete='CASCADE'))
    policy_id = Column('policy_id', Integer, ForeignKey("policies.id", ondelete='CASCADE'))
    level = Column('level', Integer, default=0)
    created_at = Column('created_at', DateTime, default=get_utc_now())
    __table_args__ = (UniqueConstraint('role_id', 'policy_id', name='role_policy'),
                      )

    roles = relationship("Roles", backref="policies_associations")
    policies = relationship("Policies", backref="roles_associations")


class UserRoles(_Base):
    """
    Relational table between User and Roles, in this table are stored the relationship between the both entities
    The information stored from User and Roles are:
        id: ID of the relationship
        user_id: ID of the user
        role_id: ID of the role
        level: Priority in case of multiples roles, higher = more priority
        created_at: Date of the relationship creation
    """
    __tablename__ = "user_roles"

    # Schema, Many-To-Many relationship
    id = Column('id', Integer, primary_key=True)
    user_id = Column('user_id', Integer, ForeignKey("users.id", ondelete='CASCADE'))
    role_id = Column('role_id', Integer, ForeignKey("roles.id", ondelete='CASCADE'))
    level = Column('level', Integer, default=0)
    created_at = Column('created_at', DateTime, default=get_utc_now())
    __table_args__ = (UniqueConstraint('user_id', 'role_id', name='user_role'),
                      )

    users = relationship("User", backref="roles_associations")
    roles = relationship("Roles", backref="users_associations")


# Declare basic tables
class RunAsTokenBlacklist(_Base):
    """
    This table contains the tokens given through the run_as endpoint that are invalid
    The information stored is:
        nbf_invalid_until: The tokens that has an nbf prior to this timestamp will be invalidated
        is_valid_until: Deadline for the rule's validity. To ensure that we can delete this rule,
        the deadline will be the time of token creation plus the time of token validity.
        This way, when we delete this rule, we ensure the invalid tokens have already expired.
    """
    __tablename__ = "runas_token_blacklist"

    nbf_invalid_until = Column('nbf_invalid_until', Integer, primary_key=True)
    is_valid_until = Column('is_valid_until', Integer, nullable=False)
    __table_args__ = (UniqueConstraint('nbf_invalid_until', name='nbf_invalid_until_invalidation_rule'),)

    def __init__(self):
        self.nbf_invalid_until = int(time())
        self.is_valid_until = self.nbf_invalid_until + security_conf['auth_token_exp_timeout']

    def to_dict(self):
        """Return the information of the token rule

        Returns
        -------
        Dict with the information
        """
        return {'nbf_invalid_until': self.nbf_invalid_until, 'is_valid_until': self.is_valid_until}


# Declare basic tables
class UsersTokenBlacklist(_Base):
    """
    This table contains the users with an invalid token and for how long
    The information stored is:
        user_id: Affected user id
        nbf_invalid_until: The tokens that has an nbf prior to this timestamp will be invalidated
        is_valid_until: Deadline for the rule's validity. To ensure that we can delete this rule,
        the deadline will be the time of token creation plus the time of token validity.
        This way, when we delete this rule, we ensure the invalid tokens have already expired.
    """
    __tablename__ = "users_token_blacklist"

    user_id = Column('user_id', Integer, primary_key=True)
    nbf_invalid_until = Column('nbf_invalid_until', Integer, nullable=False)
    is_valid_until = Column('is_valid_until', Integer, nullable=False)
    __table_args__ = (UniqueConstraint('user_id', name='user_invalidation_rule'),)

    def __init__(self, user_id):
        self.user_id = user_id
        self.nbf_invalid_until = int(time())
        self.is_valid_until = self.nbf_invalid_until + security_conf['auth_token_exp_timeout']

    def to_dict(self):
        """Return the information of the token rule

        Returns
        -------
        Dict with the information
        """
        return {'user_id': self.user_id, 'nbf_invalid_until': self.nbf_invalid_until,
                'is_valid_until': self.is_valid_until}


class RolesTokenBlacklist(_Base):
    """
    This table contains the roles with an invalid token and for how long
    The information stored is:
        role_id: Affected role id
        nbf_invalid_until: The tokens that have an nbf prior to this timestamp will be invalidated
        is_valid_until: Deadline for the rule's validity. To ensure that we can delete this rule,
        the deadline will be the time of token creation plus the time of token validity.
        This way, when we delete this rule, we ensure the invalid tokens have already expired.
    """
    __tablename__ = "roles_token_blacklist"

    role_id = Column('role_id', Integer, primary_key=True)
    nbf_invalid_until = Column('nbf_invalid_until', Integer, nullable=False)
    is_valid_until = Column('is_valid_until', Integer, nullable=False)
    __table_args__ = (UniqueConstraint('role_id', name='role_invalidation_rule'),)

    def __init__(self, role_id):
        self.role_id = role_id
        self.nbf_invalid_until = int(time())
        self.is_valid_until = self.nbf_invalid_until + security_conf['auth_token_exp_timeout']

    def to_dict(self):
        """Return the information of the token rule

        Returns
        -------
        Dict with the information
        """
        return {'role_id': self.role_id, 'nbf_invalid_until': self.nbf_invalid_until,
                'is_valid_until': self.is_valid_until}


class User(_Base):
    __tablename__ = 'users'

    id = Column('id', Integer, primary_key=True)
    username = Column(String(32), nullable=False)
    password = Column(String(256), nullable=False)
    allow_run_as = Column(Boolean, default=False, nullable=False)
    resource_type = Column(String, default=ResourceType.USER.value)
    created_at = Column('created_at', DateTime, default=get_utc_now())
    __table_args__ = (UniqueConstraint('username', name='username_restriction'),)

    # Relations
    roles = relationship("Roles", secondary='user_roles', passive_deletes=True, cascade="all,delete", lazy="dynamic")

    def __init__(self, username, password, allow_run_as=False, created_at=get_utc_now(),
                 resource_type: ResourceType = ResourceType.USER, user_id=None):
        self.id = user_id
        self.username = username
        self.password = password
        self.allow_run_as = allow_run_as
        self.created_at = created_at
        self.resource_type = resource_type.value

    def __repr__(self):
        return f"<User(user={self.username})"

    def _get_roles_id(self):
        roles = list()
        for role in self.roles:
            roles.append(role.get_role()['id'])

        return roles

    def get_roles(self):
        return list(self.roles)

    def get_user(self):
        """User's getter

        Returns
        -------
        Dict with the information of the user
        """
        return {'id': self.id, 'username': self.username,
                'roles': self._get_roles_id(), 'allow_run_as': self.allow_run_as}

    def to_dict(self, session: str = None):
        """Return the information of one policy and the roles that have assigned

        Returns
        -------
        Dict with the information
        """
        with UserRolesManager(session=session) as urm:
            return {'id': self.id, 'username': self.username,
                    'allow_run_as': self.allow_run_as,
                    'roles': [role.id for role in urm.get_all_roles_from_user(user_id=self.id)],
                    'resource_type': self.resource_type}


class Roles(_Base):
    """
    Roles table, in this table we are going to save all the information about the policies. The data that we will
    store is:
        id: ID of the policy, this is self assigned
        name: The name of the policy
        policy: The capabilities of the policy
        created_at: Date of the policy creation
    """
    __tablename__ = "roles"

    # Schema
    id = Column('id', Integer, primary_key=True)
    name = Column('name', String(20), nullable=False)
    resource_type = Column(String, default=ResourceType.USER.value)
    created_at = Column('created_at', DateTime, default=get_utc_now())
    __table_args__ = (UniqueConstraint('name', name='name_role'),
                      CheckConstraint('length(name) <= 64'))

    # Relations
    policies = relationship("Policies", secondary='roles_policies', passive_deletes=True, cascade="all,delete",
                            lazy="dynamic")
    users = relationship("User", secondary='user_roles', passive_deletes=True, cascade="all,delete", lazy="dynamic")
    rules = relationship("Rules", secondary='roles_rules', passive_deletes=True, cascade="all,delete", lazy="dynamic")

    def __init__(self, name, role_id=None, created_at=get_utc_now(), resource_type: ResourceType = ResourceType.USER):
        self.id = role_id
        self.name = name
        self.created_at = created_at
        self.resource_type = resource_type.value

    def get_role(self):
        """Role's getter

        Returns
        -------
        Dict with the information of the role
        """
        return {'id': self.id, 'name': self.name}

    def get_policies(self):
        return list(self.policies)

    def to_dict(self, session: str = None):
        """Return the information of one role and the users, policies and rules assigned to it

        Returns
        -------
        Dict with the information
        """
        with RolesPoliciesManager(session=session) as rpm:
            return {'id': self.id, 'name': self.name,
                    'policies': [policy.id for policy in rpm.get_all_policies_from_role(role_id=self.id)],
                    'users': [user.id for user in self.users],
                    'rules': [rule.id for rule in self.rules],
                    'resource_type': self.resource_type}


class Rules(_Base):
    """
    Rules table. In this table we are going to save all the information about the rules. The data that we will
    store is:
        id: ID of the rule, this is self assigned
        name: Name of the rule
        rule: Rule body
        created_at: Date of the rule creation
    """
    __tablename__ = "rules"

    # Schema
    id = Column('id', Integer, primary_key=True)
    name = Column('name', String(20), nullable=False)
    rule = Column('rule', TEXT, nullable=False)
    resource_type = Column(String, default=ResourceType.USER.value)
    created_at = Column('created_at', DateTime, default=get_utc_now())
    __table_args__ = (UniqueConstraint('name', name='rule_name'),)

    # Relations
    roles = relationship("Roles", secondary='roles_rules', passive_deletes=True, cascade="all,delete", lazy="dynamic")

    def __init__(self, name, rule, rule_id=None, created_at=get_utc_now(),
                 resource_type: ResourceType = ResourceType.USER):
        self.id = rule_id
        self.name = name
        self.rule = rule
        self.created_at = created_at
        self.resource_type = resource_type.value

    def get_rule(self):
        """Rule getter

        Returns
        -------
        Dict with the information of the rule
        """
        return {'id': self.id, 'name': self.name, 'rule': json.loads(self.rule)}

    def to_dict(self):
        """Return the information of one rule and its roles

        Returns
        -------
        Dict with the information
        """
        return {'id': self.id, 'name': self.name, 'rule': json.loads(self.rule),
                'roles': [role.id for role in self.roles],
                'resource_type': self.resource_type}


class Policies(_Base):
    """
    Policies table, in this table we are going to save all the information about the policies. The data that we will
    store is:
        id: ID of the policy, this is self assigned
        name: The name of the policy
        policy: The capabilities of the policy
        created_at: Date of the policy creation
    """
    __tablename__ = "policies"

    # Schema
    id = Column('id', Integer, primary_key=True)
    name = Column('name', String(20), nullable=False)
    policy = Column('policy', TEXT, nullable=False)
    resource_type = Column(String, default=ResourceType.USER.value)
    created_at = Column('created_at', DateTime, default=get_utc_now())
    __table_args__ = (UniqueConstraint('name', name='name_policy'),
                      UniqueConstraint('policy', name='policy_definition'))

    # Relations
    roles = relationship("Roles", secondary='roles_policies', passive_deletes=True, cascade="all,delete",
                         lazy="dynamic")

    def __init__(self, name, policy, policy_id=None, created_at=get_utc_now(),
                 resource_type: ResourceType = ResourceType.USER):
        self.id = policy_id
        self.name = name
        self.policy = policy
        self.created_at = created_at
        self.resource_type = resource_type.value

    def get_policy(self):
        """Policy's getter

        Returns
        -------
        Dict with the information of the policy
        """
        return {'id': self.id, 'name': self.name, 'policy': json.loads(self.policy)}

    def to_dict(self, session: str = None):
        """Return the information of one policy and the roles that have assigned

        Returns
        -------
        Dict with the information
        """
        with RolesPoliciesManager(session=session) as rpm:
            return {'id': self.id, 'name': self.name, 'policy': json.loads(self.policy),
                    'roles': [role.id for role in rpm.get_all_roles_from_policy(policy_id=self.id)],
                    'resource_type': self.resource_type}


class TokenManager:
    """
    This class is the manager of Token blacklist, this class provides
    all the methods needed for the token blacklist administration.
    """

    def is_token_valid(self, token_nbf_time: int, user_id: int = None, role_id: int = None, run_as: bool = False):
        """Check if specified token is valid

        Parameters
        ----------
        user_id : int
            Current token's user id
        role_id : int
            Current token's role id
        token_nbf_time : int
            Token's issue timestamp
        run_as : bool
            Indicate if the token has been granted through run_as endpoint

        Returns
        -------
        True if is valid, False if not
        """
        try:
            user_rule = self.session.query(UsersTokenBlacklist).filter_by(user_id=user_id).first()
            role_rule = self.session.query(RolesTokenBlacklist).filter_by(role_id=role_id).first()
            runas_rule = self.session.query(RunAsTokenBlacklist).first()
            return (not user_rule or (token_nbf_time > user_rule.nbf_invalid_until)) and \
                   (not role_rule or (token_nbf_time > role_rule.nbf_invalid_until)) and \
                   (not run_as or (not runas_rule or (token_nbf_time > runas_rule.nbf_invalid_until)))
        except IntegrityError:
            return True

    def get_all_rules(self):
        """Return two dictionaries where keys are role_ids and user_ids and the value of each them is nbf_invalid_until

        Returns
        -------
        dict
        """
        try:
            users_format_rules, roles_format_rules, runas_format_rule = dict(), dict(), dict()
            users_rules = map(UsersTokenBlacklist.to_dict, self.session.query(UsersTokenBlacklist).all())
            roles_rules = map(RolesTokenBlacklist.to_dict, self.session.query(RolesTokenBlacklist).all())
            runas_rule = self.session.query(RunAsTokenBlacklist).first()
            if runas_rule:
                runas_rule = runas_rule.to_dict()
                runas_format_rule['run_as'] = runas_rule['nbf_invalid_until']
            for rule in list(users_rules):
                users_format_rules[rule['user_id']] = rule['nbf_invalid_until']
            for rule in list(roles_rules):
                roles_format_rules[rule['role_id']] = rule['nbf_invalid_until']

            return users_format_rules, roles_format_rules, runas_format_rule
        except IntegrityError:
            return SecurityError.TOKEN_RULE_NOT_EXIST

    def add_user_roles_rules(self, users: set = None, roles: set = None, run_as: bool = False):
        """Add new rules for users-token or roles-token.
        Both, nbf_invalid_until and is_valid_until are generated automatically

        Parameters
        ----------
        users : set
            Set with the affected users
        roles : set
            Set with the affected roles
        run_as : bool
            Indicate if the token has been granted through run_as endpoint

        Returns
        -------
        True if the success, SecurityError.ALREADY_EXIST if failed
        """
        if users is None:
            users = set()
        if roles is None:
            roles = set()

        try:
            self.delete_all_expired_rules()
            for user_id in users:
                self.delete_rule(user_id=int(user_id))
                self.session.add(UsersTokenBlacklist(user_id=int(user_id)))
                self.session.commit()
            for role_id in roles:
                self.delete_rule(role_id=int(role_id))
                self.session.add(RolesTokenBlacklist(role_id=int(role_id)))
                self.session.commit()
            if run_as:
                self.delete_rule(run_as=run_as)
                self.session.add(RunAsTokenBlacklist())
                self.session.commit()

            clear_cache()
            return True
        except IntegrityError:
            self.session.rollback()
            return SecurityError.ALREADY_EXIST

    def delete_rule(self, user_id: int = None, role_id: int = None, run_as: bool = False):
        """Remove the rule for the specified role

        Parameters
        ----------
        user_id : int
            Desired user_id
        role_id : int
            Desired role_id
        run_as : bool
            Indicate if the token has been granted through run_as endpoint

        Returns
        -------
        True if success, SecurityError.TOKEN_RULE_NOT_EXIST if failed
        """
        try:
            self.session.query(UsersTokenBlacklist).filter_by(user_id=user_id).delete()
            self.session.query(RolesTokenBlacklist).filter_by(role_id=role_id).delete()
            if run_as:
                run_as_rule = self.session.query(RunAsTokenBlacklist).first()
                run_as_rule and self.session.delete(run_as_rule)
            self.session.commit()

            return True
        except IntegrityError:
            self.session.rollback()
            return SecurityError.TOKEN_RULE_NOT_EXIST

    def delete_all_expired_rules(self):
        """Delete all expired rules in the system

        Returns
        -------
        List of removed user and role rules
        """
        try:
            list_users, list_roles = list(), list()
            current_time = int(time())
            users_tokens_in_blacklist = self.session.query(UsersTokenBlacklist).all()
            for user_token in users_tokens_in_blacklist:
                token_rule = self.session.query(UsersTokenBlacklist).filter_by(user_id=user_token.user_id)
                if token_rule.first() and current_time > token_rule.first().is_valid_until:
                    token_rule.delete()
                    self.session.commit()
                    list_users.append(user_token.user_id)
            roles_tokens_in_blacklist = self.session.query(RolesTokenBlacklist).all()
            for role_token in roles_tokens_in_blacklist:
                token_rule = self.session.query(RolesTokenBlacklist).filter_by(role_id=role_token.role_id)
                if token_rule.first() and current_time > token_rule.first().is_valid_until:
                    token_rule.delete()
                    self.session.commit()
                    list_roles.append(role_token.role_id)
            runas_token_in_blacklist = self.session.query(RunAsTokenBlacklist).first()
            if runas_token_in_blacklist and runas_token_in_blacklist.to_dict()['is_valid_until'] < current_time:
                self.session.delete(runas_token_in_blacklist)
                self.session.commit()

            return list_users, list_roles
        except IntegrityError:
            self.session.rollback()
            return False

    def delete_all_rules(self):
        """Delete all existent rules in the system

        Returns
        -------
        List of removed user and role rules
        """
        try:
            list_users, list_roles = list(), list()
            users_tokens_in_blacklist = self.session.query(UsersTokenBlacklist).all()
            roles_tokens_in_blacklist = self.session.query(RolesTokenBlacklist).all()
            clean = False
            for user_token in users_tokens_in_blacklist:
                list_roles.append(user_token.user_id)
                self.session.query(UsersTokenBlacklist).filter_by(user_id=user_token.user_id).delete()
                clean = True
            for role_token in roles_tokens_in_blacklist:
                list_roles.append(role_token.role_id)
                self.session.query(RolesTokenBlacklist).filter_by(role_id=role_token.role_id).delete()
                clean = True
            runas_rule = self.session.query(RunAsTokenBlacklist).first()
            if runas_rule:
                self.session.delete(runas_rule)
                clean = True

            clean and self.session.commit()
            return list_users, list_roles
        except IntegrityError:
            self.session.rollback()
            return False

    def __enter__(self):
        self.session = _Session()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.session.close()


class AuthenticationManager:
    """Class for dealing with authentication stuff without worrying about database.
    It manages users and token generation.
    """

    def __init__(self, session=None):
        self.session = session or sessionmaker(bind=create_engine(f"sqlite:///{_db_file}", echo=False))()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.session.close()

    def edit_run_as(self, user_id: int, allow_run_as: bool):
        """Change the specified user's allow_run_as flag.

        Parameters
        ----------
        user_id : int
            Unique user id
        allow_run_as : bool
            Flag that indicates if the user can log into the API through an authorization context

        Returns
        -------
        True if the user's flag has been modified successfully.
        INVALID if the specified value is not correct. False otherwise.
        """
        try:
            user = self.session.query(User).filter_by(id=user_id).first()
            if user is not None:
                if isinstance(allow_run_as, bool):
                    user.allow_run_as = allow_run_as
                    self.session.commit()
                    return True
                return SecurityError.INVALID
            return False
        except IntegrityError:
            self.session.rollback()
            return False

    def add_user(self, username: str, password: str, user_id: int = None, hash_password: bool = False,
                 created_at: datetime = get_utc_now(), resource_type: ResourceType = ResourceType.USER,
                 check_default: bool = True) -> bool:
        """Create a new user if it does not exist. TODO update

        Parameters
        ----------
        username : str
            Unique user name
        password : str
            Password provided by user. It will be stored hashed
        check_default : bool
            Flag that indicates if the user ID can be less than max_id_reserved

        Returns
        -------
        True if the user has been created successfully. False otherwise (i.e. already exists)
        """
        try:
            try:
                if check_default and self.session.query(User).order_by(desc(User.id)
                                                                       ).limit(1).scalar().id < max_id_reserved:
                    user_id = max_id_reserved + 1
            except (TypeError, AttributeError):
                pass
            self.session.add(User(username=username,
                                  password=password if hash_password else generate_password_hash(password),
                                  created_at=created_at,
                                  resource_type=resource_type,
                                  user_id=user_id))
            self.session.commit()
            return True
        except IntegrityError:
            self.session.rollback()
            return False

    def update_user(self, user_id: int, password: str, resource_type: ResourceType = None) -> bool:
        """Update the password an existent user TODO update

        Parameters
        ----------
        user_id : int
            Unique user id
        password : str
            Password provided by user. It will be stored hashed

        Returns
        -------
        True if the user has been modify successfully. False otherwise
        """
        try:
            user = self.session.query(User).filter_by(id=user_id).first()
            if user is not None:
                if resource_type is not None:
                    user.resource_type = resource_type.value
                if password:
                    user.password = generate_password_hash(password)
                if password or resource_type:
                    self.session.commit()
                    return True
            return False
        except IntegrityError:
            self.session.rollback()
            return False

    def delete_user(self, user_id: int):
        """Remove the specified user

        Parameters
        ----------
        user_id : int
            Unique user id

        Returns
        -------
        True if the user has been delete successfully. False otherwise
        """
        try:
            if user_id > max_id_reserved:
                user = self.session.query(User).filter_by(id=user_id).first()
                if user is None:
                    return False
                self.session.delete(user)
                self.session.commit()
                return True
            return SecurityError.ADMIN_RESOURCES
        except UnmappedInstanceError:
            # User already deleted
            return False

    def check_user(self, username, password):
        """Validates a username-password pair.

        :param username: string Unique user name
        :param password: string Password to be checked against the one saved in the database
        :return: True if username and password matches. False otherwise.
        """
        user = self.session.query(User).filter_by(username=username).first()
        return check_password_hash(user.password, password) if user else False

    def get_user(self, username: str = None):
        """Get an specified user in the system
        :param username: string Unique user name
        :return: An specified user
        """
        try:
            if username is not None:
                return self.session.query(User).filter_by(username=username).first().to_dict(self.session)
        except (IntegrityError, AttributeError):
            self.session.rollback()
            return False

    def get_user_id(self, user_id: int):
        """Get a specified user in the system.

        Parameters
        ----------
        user_id : int
            Unique user id

        Returns
        -------
        Information about the specified user
        """
        try:
            if user_id is not None:
                return self.session.query(User).filter_by(id=user_id).first().to_dict(self.session)
        except (IntegrityError, AttributeError):
            self.session.rollback()
            return False

    def user_allow_run_as(self, username: str = None):
        """Get the allow_run_as's flag of specified user in the system

        :param username: string Unique user name
        :return: An specified user
        """
        try:
            if username is not None:
                return self.session.query(User).filter_by(username=username).first().get_user()['allow_run_as']
        except (IntegrityError, AttributeError):
            self.session.rollback()
            return False

    def get_users(self):
        """Get all users in the system

        :return: All users
        """
        try:
            users = self.session.query(User).all()
        except IntegrityError:
            self.session.rollback()
            return False

        user_ids = list()
        for user in users:
            if user is not None:
                user_dict = {
                    'user_id': user.id,
                    'username': user.username
                }
                user_ids.append(user_dict)
        return user_ids


class RolesManager:
    """
    This class is the manager of the Roles, this class provided
    all the methods needed for the roles administration.
    """

    def __init__(self, session=None):
        self.session = session or sessionmaker(bind=create_engine(f"sqlite:///{_db_file}", echo=False))()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.session.close()

    def get_role(self, name: str):
        """Get the information about one role specified by name

        Parameters
        ----------
        name : str
            Name of the rol that want to get its information

        Returns
        -------
        Role object with all of its information
        """
        try:
            role = self.session.query(Roles).filter_by(name=name).first()
            if not role:
                return SecurityError.ROLE_NOT_EXIST
            return role.to_dict(self.session)
        except IntegrityError:
            return SecurityError.ROLE_NOT_EXIST

    def get_role_id(self, role_id: int):
        """Get the information about one role specified by id

        Parameters
        ----------
        role_id : int
            ID of the rol that want to get its information

        Returns
        -------
        Role object with all of its information
        """
        try:
            role = self.session.query(Roles).filter_by(id=role_id).first()
            if not role:
                return SecurityError.ROLE_NOT_EXIST
            return role.to_dict(self.session)
        except IntegrityError:
            return SecurityError.ROLE_NOT_EXIST

    def get_roles(self):
        """Get the information about all roles in the system

        Returns
        -------
        List of Roles objects with all of its information | False -> No roles in the system
        """
        try:
            roles = self.session.query(Roles).all()
            return roles
        except IntegrityError:
            return SecurityError.ROLE_NOT_EXIST

    def add_role(self, name: str, role_id: int = None, created_at: datetime = get_utc_now(),
                 resource_type: ResourceType = ResourceType.USER, check_default: bool = True) -> Union[bool,
                                                                                                       SecurityError]:
        """Add a new role. TODO update

        Parameters
        ----------
        name : str
            Name of the new role
        check_default : bool
            Flag that indicates if the user ID can be less than max_id_reserved

        Returns
        -------
        True -> Success | Role already exist
        """
        try:
            try:
                if check_default and self.session.query(Roles).order_by(desc(Roles.id)
                                                                        ).limit(1).scalar().id < max_id_reserved:
                    role_id = max_id_reserved + 1
            except (TypeError, AttributeError):
                pass
            self.session.add(Roles(name=name, role_id=role_id, created_at=created_at, resource_type=resource_type))
            self.session.commit()
            return True
        except IntegrityError:
            self.session.rollback()
            return SecurityError.ALREADY_EXIST

    def delete_role(self, role_id: int):
        """Delete an existent role in the system

        Parameters
        ----------
        role_id : int
            ID of the role to be deleted

        Returns
        -------
        True -> Success | False -> Failure
        """
        try:
            if role_id > max_id_reserved:
                role = self.session.query(Roles).filter_by(id=role_id).first()
                if role is None:
                    return False
                self.session.delete(role)
                self.session.commit()
                return True
            return SecurityError.ADMIN_RESOURCES
        except IntegrityError:
            self.session.rollback()
            return False

    def delete_role_by_name(self, role_name: str):
        """Delete an existent role in the system

        Parameters
        ----------
        role_name : str
            Name of the role to be deleted

        Returns
        -------
        True -> Success | False -> Failure
        """
        try:
            if self.get_role(role_name) is not None and self.get_role(role_name)['id'] > max_id_reserved:
                role_id = self.session.query(Roles).filter_by(name=role_name).first().id
                if role_id:
                    self.delete_role(role_id=role_id)
                    return True
            return False
        except (IntegrityError, AttributeError):
            self.session.rollback()
            return False

    def delete_all_roles(self):
        """Delete all existent roles in the system

        Returns
        -------
        List of ids of deleted roles -> Success | False -> Failure
        """
        try:
            list_roles = list()
            roles = self.session.query(Roles).all()
            for role in roles:
                if int(role.id) > max_id_reserved:
                    self.session.delete(self.session.query(Roles).filter_by(id=role.id).first())
                    self.session.commit()
                    list_roles.append(int(role.id))
            return list_roles
        except IntegrityError:
            self.session.rollback()
            return False

    def update_role(self, role_id: int, name: str, resource_type: ResourceType = None) -> Union[bool, SecurityError]:
        """Update an existent role in the system TODO update

        Parameters
        ----------
        role_id : int
            ID of the role to be updated
        name : str
            New name for the role

        Returns
        -------
        True -> Success | Invalid rule | Name already in use | Role not exist
        """
        try:
            if role_id > max_id_reserved:
                role = self.session.query(Roles).filter_by(id=role_id).first()
                if role is not None:
                    if name is not None:
                        role.name = name
                    if resource_type is not None:
                        role.resource_type = resource_type.value
                    if name or resource_type:
                        self.session.commit()
                        return True
                return SecurityError.ROLE_NOT_EXIST
            return SecurityError.ADMIN_RESOURCES
        except IntegrityError:
            self.session.rollback()
            return SecurityError.ALREADY_EXIST


class RulesManager:
    """
        This class is Rules manager. This class provides all the methods needed for the rules administration.
        """

    def __init__(self, session=None):
        self.session = session or sessionmaker(bind=create_engine(f"sqlite:///{_db_file}", echo=False))()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.session.close()

    def get_rule(self, rule_id: int):
        """Get the information about one rule specified by id.

        Parameters
        ----------
        rule_id : int
            ID of the rule.

        Returns
        -------
        Rule object with all its information.
        """
        try:
            rule = self.session.query(Rules).filter_by(id=rule_id).first()
            if not rule:
                return SecurityError.RULE_NOT_EXIST
            return rule.to_dict()
        except IntegrityError:
            return SecurityError.RULE_NOT_EXIST

    def get_rule_by_name(self, rule_name: str):
        """Get the information about one rule specified by name.

        Parameters
        ----------
        rule_name : str
            Name of the rule.

        Returns
        -------
        Rule object with all its information.
        """
        try:
            rule = self.session.query(Rules).filter_by(name=rule_name).first()
            if not rule:
                return SecurityError.RULE_NOT_EXIST
            return rule.to_dict()
        except IntegrityError:
            return SecurityError.RULE_NOT_EXIST

    def get_rules(self):
        """Get the information about all rules in the system.

        Returns
        -------
        List of Rule objects with all of its information | False -> No rules in the system
        """
        try:
            rules = self.session.query(Rules).all()
            return rules
        except IntegrityError:
            return SecurityError.RULE_NOT_EXIST

    def add_rule(self, name: str, rule: dict, rule_id: int = None, created_at: datetime = None,
                 resource_type: ResourceType = ResourceType.USER, check_default: bool = True) -> Union[bool,
                                                                                                       SecurityError]:
        """Add a new rule. # TODO update

        Parameters
        ----------
        name : str
            Name of the new rule.
        rule : dict
            Rule dictionary.
        check_default : bool
            Flag that indicates if the user ID can be less than max_id_reserved

        Returns
        -------
        True -> Success | Rule already exists | Invalid rule
        """
        try:
            if rule is not None and not json_validator(rule):
                return SecurityError.INVALID
            try:
                if check_default and \
                        self.session.query(Rules).order_by(desc(Rules.id)
                                                           ).limit(1).scalar().id < max_id_reserved:
                    rule_id = max_id_reserved + 1
            except (TypeError, AttributeError):
                pass
            self.session.add(Rules(name=name, rule=json.dumps(rule), rule_id=rule_id, resource_type=resource_type))
            self.session.commit()
            return True
        except IntegrityError:
            self.session.rollback()
            return SecurityError.ALREADY_EXIST

    def delete_rule(self, rule_id: int):
        """Delete an existent rule from the system specified by its ID.

        Parameters
        ----------
        rule_id : int
            Id of the rule.
        Returns
        -------
        True -> Success | False -> Failure
        """
        try:
            if rule_id > max_id_reserved:
                rule = self.session.query(Rules).filter_by(id=rule_id).first()
                if rule is None:
                    return False
                self.session.delete(rule)
                self.session.commit()
                return True
            return SecurityError.ADMIN_RESOURCES
        except IntegrityError:
            self.session.rollback()
            return False

    def delete_rule_by_name(self, rule_name: str):
        """Delete an existent rule from the system specified by its name.

        Parameters
        ----------
        rule_name : str
            Name of the rule.
        Returns
        -------
        True -> Success | False -> Failure | ADMIN_RESOURCES -> Admin rules cannot be deleted
        """
        try:
            if self.get_rule_by_name(rule_name) is not None and \
                    self.get_rule_by_name(rule_name)['id'] > max_id_reserved:
                rule_id = self.session.query(Rules).filter_by(name=rule_name).first().id
                if rule_id:
                    self.delete_rule(rule_id=rule_id)
                    return True
            return False
        except (IntegrityError, AttributeError):
            self.session.rollback()
            return False

    def delete_all_rules(self):
        """Delete all existent rules from the system.

        Returns
        -------
        List of deleted rules -> Success | False -> Failure
        """
        try:
            list_rules = list()
            rules = self.session.query(Rules).all()
            for rule in rules:
                if int(rule.id) > max_id_reserved:
                    self.session.delete(self.session.query(Rules).filter_by(id=rule.id).first())
                    self.session.commit()
                    list_rules.append(int(rule.id))
            return list_rules
        except IntegrityError:
            self.session.rollback()
            return False

    def update_rule(self, rule_id: int, name: str, rule: dict, resource_type: ResourceType = None) \
            -> Union[bool, SecurityError]:
        """Update an existent rule in the system. TODO update

        Parameters
        ----------
        rule_id : int
            ID of the rule.
        name : name
            Name of the rule.
        rule : dict
            Dictionary with the rule itself.

        Returns
        -------
        True -> Success | Invalid rule | Name already in use | Rule already in use | Rule not exists
        """
        try:
            if rule_id > max_id_reserved:
                rule_to_update = self.session.query(Rules).filter_by(id=rule_id).first()
                if rule_to_update is not None:
                    if not json_validator(rule):
                        return SecurityError.INVALID
                    if name is not None:
                        rule_to_update.name = name
                    if rule is not None:
                        rule_to_update.rule = json.dumps(rule)
                    if resource_type is not None:
                        rule_to_update.resource_type = resource_type.value
                    if rule or name or resource_type:
                        self.session.commit()
                        return True
                return SecurityError.RULE_NOT_EXIST
            return SecurityError.ADMIN_RESOURCES
        except IntegrityError:
            self.session.rollback()
            return SecurityError.ALREADY_EXIST


class PoliciesManager:
    """
    This class is the manager of the Policies, this class provided
    all the methods needed for the policies administration.
    """
    action_regex = r'^[a-zA-Z_\-]+:[a-zA-Z_\-]+$'
    resource_regex = r'^[a-zA-Z_\-*]+:[\w_\-*]+:[\w_\-\/.*]+$'

    def __init__(self, session=None):
        self.session = session or sessionmaker(bind=create_engine(f"sqlite:///{_db_file}", echo=False))()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.session.close()

    def get_policy(self, name: str):
        """Get the information about one policy specified by name

        Parameters
        ----------
        name : str
            Name of the policy that want to get its information

        Returns
        -------
        Policy object with all of its information
        """
        try:
            policy = self.session.query(Policies).filter_by(name=name).first()
            if not policy:
                return SecurityError.POLICY_NOT_EXIST
            return policy.to_dict(self.session)
        except IntegrityError:
            return SecurityError.POLICY_NOT_EXIST

    def get_policy_id(self, policy_id: int):
        """Get the information about one policy specified by id

        Parameters
        ----------
        policy_id : int
            ID of the policy that want to get its information

        Returns
        -------
        Policy object with all of its information
        """
        try:
            policy = self.session.query(Policies).filter_by(id=policy_id).first()
            if not policy:
                return SecurityError.POLICY_NOT_EXIST
            return policy.to_dict(self.session)
        except IntegrityError:
            return SecurityError.POLICY_NOT_EXIST

    def get_policies(self):
        """Get the information about all policies in the system

        Returns
        -------
        List of policies objects with all of its information | False -> No policies in the system
        """
        try:
            policies = self.session.query(Policies).all()
            return policies
        except IntegrityError:
            return SecurityError.POLICY_NOT_EXIST

    def add_policy(self, name: str, policy: dict, policy_id: int = None, created_at: datetime = get_utc_now(),
                   resource_type: ResourceType = ResourceType.USER, check_default: bool = True) -> Union[bool,
                                                                                                         SecurityError]:
        """Add a new policy. TODO update

        Parameters
        ----------
        name : str
            Name of the new policy
        policy : dict
            Policy of the new policy
        check_default : bool
            Flag that indicates if the user ID can be less than max_id_reserved

        Returns
        -------
        True -> Success | Invalid policy | Missing key (actions, resources, effect) or invalid policy (regex)
        """
        try:
            if policy is not None and not json_validator(policy):
                return SecurityError.ALREADY_EXIST
            if policy is None or len(policy) != 3:
                return SecurityError.INVALID
            # To add a policy it must have the keys actions, resources, effect
            if 'actions' in policy and 'resources' in policy:
                if 'effect' in policy:
                    # The keys actions and resources must be lists and the key effect must be str
                    if isinstance(policy['actions'], list) and isinstance(policy['resources'], list) \
                            and isinstance(policy['effect'], str):
                        for action in policy['actions']:
                            if not re.match(self.action_regex, action):
                                return SecurityError.INVALID
                        for resource in policy['resources']:
                            if not all(re.match(self.resource_regex, res) for res in resource.split('&')):
                                return SecurityError.INVALID

                        try:
                            if not check_default:
                                policies = sorted([p.id for p in self.get_policies()]) or [0]
                                policy_id = policy_id or max(filter(lambda x: not (x > cloud_reserved_range),
                                                                    policies)) + 1

                            elif check_default and \
                                    self.session.query(Policies).order_by(desc(Policies.id)
                                                                          ).limit(1).scalar().id < max_id_reserved:
                                policy_id = max_id_reserved + 1

                        except (TypeError, AttributeError):
                            pass
                        self.session.add(Policies(name=name, policy=json.dumps(policy), policy_id=policy_id,
                                                  created_at=created_at, resource_type=resource_type))
                        self.session.commit()
                        return True
                    else:
                        return SecurityError.INVALID
                else:
                    return SecurityError.INVALID
            else:
                return SecurityError.INVALID
        except IntegrityError:
            self.session.rollback()
            return SecurityError.ALREADY_EXIST

    def delete_policy(self, policy_id: int):
        """Delete an existent policy in the system

        Parameters
        ----------
        policy_id : int
            ID of the policy to be deleted

        Returns
        -------
        True -> Success | False -> Failure
        """
        try:
            if int(policy_id) > max_id_reserved:
                policy = self.session.query(Policies).filter_by(id=policy_id).first()
                if policy is None:
                    return False
                self.session.delete(policy)
                self.session.commit()
                return True
            return SecurityError.ADMIN_RESOURCES
        except IntegrityError:
            self.session.rollback()
            return False

    def delete_policy_by_name(self, policy_name: str):
        """Delete an existent role in the system

        Parameters
        ----------
        policy_name : str
            Name of the policy to be deleted

        Returns
        -------
        True -> Success | False -> Failure
        """
        try:
            if self.get_policy(policy_name) is not None and \
                    self.get_policy(name=policy_name)['id'] > max_id_reserved:
                policy_id = self.session.query(Policies).filter_by(name=policy_name).first().id
                if policy_id:
                    self.delete_policy(policy_id=policy_id)
                    return True
            return False
        except (IntegrityError, AttributeError):
            self.session.rollback()
            return False

    def delete_all_policies(self):
        """Delete all existent policies in the system

        Returns
        -------
        List of ids of deleted policies -> Success | False -> Failure
        """
        try:
            list_policies = list()
            policies = self.session.query(Policies).all()
            for policy in policies:
                if int(policy.id) > max_id_reserved:
                    self.session.delete(self.session.query(Policies).filter_by(id=policy.id).first())
                    self.session.commit()
                    list_policies.append(int(policy.id))
            return list_policies
        except IntegrityError:
            self.session.rollback()
            return False

    def update_policy(self, policy_id: int, name: str, policy: dict, resource_type: ResourceType = None,
                      check_default: bool = True) \
            -> Union[bool, SecurityError]:
        """Update an existent policy in the system TODO update

        Parameters
        ----------
        policy_id : int
            ID of the Policy to be updated
        name : str
            New name for the Policy
        policy : dict
            New policy for the Policy
        check_default : bool, optional
            Flag that indicates if the policy ID can be less than `max_id_reserved`.

        Returns
        -------
        True -> Success | False -> Failure | Invalid policy | Name already in use
        """
        try:
            if policy_id > max_id_reserved or not check_default:
                policy_to_update = self.session.query(Policies).filter_by(id=policy_id).first()
                if policy_to_update:
                    if not json_validator(policy):
                        return SecurityError.INVALID
                    if name is not None:
                        policy_to_update.name = name
                    if policy is not None and 'actions' in policy.keys() and \
                            'resources' in policy and 'effect' in policy:
                        for action in policy['actions']:
                            if not re.match(self.action_regex, action):
                                return SecurityError.INVALID
                        for resource in policy['resources']:
                            if not all(re.match(self.resource_regex, res) for res in resource.split('&')):
                                return SecurityError.INVALID
                        policy_to_update.policy = json.dumps(policy)
                    if resource_type is not None:
                        policy_to_update.resource_type = resource_type.value
                    if name or policy or resource_type:
                        self.session.commit()
                        return True
                return SecurityError.POLICY_NOT_EXIST
            return SecurityError.ADMIN_RESOURCES
        except IntegrityError:
            self.session.rollback()
            return SecurityError.ALREADY_EXIST


class UserRolesManager:
    """
    This class is the manager of the relationship between the user and the roles, this class provided
    all the methods needed for the user-roles administration.
    """

    def __init__(self, session=None):
        self.session = session or sessionmaker(bind=create_engine(f"sqlite:///{_db_file}", echo=False))()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.session.close()

    def add_role_to_user(self, user_id: int, role_id: int, position: int = None, created_at: datetime = get_utc_now(),
                         force_admin: bool = False, atomic: bool = True) -> Union[bool, SecurityError]:
        """Add a relation between one specified user and one specified role.

        Parameters
        ----------
        user_id : int
            ID of the user
        role_id : int
            ID of the role
        position : int
            Order to be applied in case of multiples roles in the same user
        force_admin : bool
            By default, changing an administrator user is not allowed. If True, it will be applied to admin users too
        atomic : bool
            This parameter indicates if the operation is atomic. If this function is called within
            a loop or a function composed of several operations, atomicity cannot be guaranteed.
            And it must be the most external function that ensures it

        Returns
        -------
        True -> Success | False -> Failure | User not found | Role not found | Existing relationship | Invalid level
        """
        try:
            # Create a role-policy relationship if both exist
            if user_id > max_id_reserved or force_admin:
                user = self.session.query(User).filter_by(id=user_id).first()
                if user is None:
                    return SecurityError.USER_NOT_EXIST
                role = self.session.query(Roles).filter_by(id=role_id).first()
                if role is None:
                    return SecurityError.ROLE_NOT_EXIST
                if position is not None or \
                        self.session.query(UserRoles).filter_by(user_id=user_id, role_id=role_id).first() is None:
                    if position is not None and \
                            self.session.query(UserRoles).filter_by(user_id=user_id, level=position).first() and \
                            self.session.query(UserRoles).filter_by(user_id=user_id, role_id=role_id).first() is None:
                        user_roles = [row for row in self.session.query(
                            UserRoles).filter(UserRoles.user_id == user_id, UserRoles.level >= position
                                              ).order_by(UserRoles.level).all()]
                        new_level = position
                        for relation in user_roles:
                            relation.level = new_level + 1
                            new_level += 1

                    user.roles.append(role)
                    user_role = self.session.query(UserRoles).filter_by(user_id=user_id, role_id=role_id).first()
                    if position is None:
                        roles = user.get_roles()
                        position = len(roles) - 1
                    else:
                        max_position = max([row.level for row in self.session.query(UserRoles).filter_by(
                            user_id=user_id).all()])
                        if max_position == 0 and len(list(user.roles)) - 1 == 0:
                            position = 0
                        elif position > max_position + 1:
                            position = max_position + 1
                    user_role.level = position
                    user_role.created_at = created_at

                    atomic and self.session.commit()
                    return True
                else:
                    return SecurityError.ALREADY_EXIST
            return SecurityError.ADMIN_RESOURCES
        except (IntegrityError, InvalidRequestError):
            self.session.rollback()
            return SecurityError.INVALID

    def add_user_to_role(self, user_id: int, role_id: int, position: int = -1, atomic: bool = True):
        """Clone of the previous function.

        Parameters
        ----------
        user_id : int
            ID of the user
        role_id : int
            ID of the role
        position : int
            Order to be applied in case of multiples roles in the same user
        atomic : bool
            This parameter indicates if the operation is atomic. If this function is called within
            a loop or a function composed of several operations, atomicity cannot be guaranteed.
            And it must be the most external function that ensures it

        Returns
        -------
        True -> Success | False -> Failure | User not found | Role not found | Existing relationship | Invalid level
        """
        return self.add_role_to_user(user_id=user_id, role_id=role_id, position=position, atomic=atomic)

    def get_all_roles_from_user(self, user_id: int):
        """Get all the roles related with the specified user.

        Parameters
        ----------
        user_id : int
            ID of the user

        Returns
        -------
        List of roles related with the user -> Success | False -> Failure
        """
        try:
            user_roles = self.session.query(UserRoles).filter_by(user_id=user_id).order_by(UserRoles.level).all()
            roles = list()
            for relation in user_roles:
                roles.append(self.session.query(Roles).filter_by(id=relation.role_id).first())
            return roles
        except (IntegrityError, AttributeError):
            self.session.rollback()
            return False

    def get_all_users_from_role(self, role_id: int):
        """Get all the users related with the specified role.

        Parameters
        ----------
        role_id : int
            ID of the role

        Returns
        -------
        List of users related with the role -> Success | False -> Failure
        """
        try:
            role = self.session.query(Roles).filter_by(id=role_id).first()
            return map(partial(User.to_dict, session=self.session), role.users)
        except (IntegrityError, AttributeError):
            self.session.rollback()
            return False

    def exist_user_role(self, user_id: int, role_id: int):
        """Check if the relationship user-role exist.

        Parameters
        ----------
        user_id : int
            ID of the user
        role_id : int
            ID of th role

        Returns
        -------
        True -> Existent relationship | False -> Failure | User not exist
        """
        try:
            user = self.session.query(User).filter_by(id=user_id).first()
            if user is None:
                return SecurityError.USER_NOT_EXIST
            role = self.session.query(Roles).filter_by(id=role_id).first()
            if role is None:
                return SecurityError.ROLE_NOT_EXIST
            role = user.roles.filter_by(id=role_id).first()
            if role is not None:
                return True
            return False
        except IntegrityError:
            self.session.rollback()
            return False

    def exist_role_user(self, user_id: int, role_id: int):
        """Clone of the previous function.

        Parameters
        ----------
        user_id : int
            ID of the user
        role_id : int
            ID of th role

        Returns
        -------
        True -> Existent relationship | False -> Failure | User not exist
        """
        return self.exist_user_role(user_id=user_id, role_id=role_id)

    def remove_role_in_user(self, user_id: int, role_id: int, atomic: bool = True):
        """Remove a user-role relationship if both exist.

        Parameters
        ----------
        user_id : int
            ID of the user
        role_id : int
            ID of the role
        atomic : bool
            This parameter indicates if the operation is atomic. If this function is called within
            a loop or a function composed of several operations, atomicity cannot be guaranteed.
            And it must be the most external function that ensures it

        Returns
        -------
        True -> Success | False -> Failure | User not exist | Role not exist | Non-existent relationship
        """
        try:
            if user_id > max_id_reserved:  # Administrator
                user = self.session.query(User).filter_by(id=user_id).first()
                if user is None:
                    return SecurityError.USER_NOT_EXIST
                role = self.session.query(Roles).filter_by(id=role_id).first()
                if role is None:
                    return SecurityError.ROLE_NOT_EXIST
                if self.session.query(UserRoles).filter_by(user_id=user_id, role_id=role_id).first() is not None:
                    user = self.session.query(User).get(user_id)
                    role = self.session.query(Roles).get(role_id)
                    user.roles.remove(role)
                    atomic and self.session.commit()
                    return True
                else:
                    return SecurityError.INVALID
            return SecurityError.ADMIN_RESOURCES
        except IntegrityError:
            self.session.rollback()
            return SecurityError.INVALID

    def remove_user_in_role(self, user_id: int, role_id: int, atomic: bool = True):
        """Clone of the previous function.

        Parameters
        ----------
        user_id : int
            ID of the user
        role_id : int
            ID of the role
        atomic : bool
            This parameter indicates if the operation is atomic. If this function is called within
            a loop or a function composed of several operations, atomicity cannot be guaranteed.
            And it must be the most external function that ensures it

        Returns
        -------
        True -> Success | False -> Failure | User not exist | Role not exist | Non-existent relationship
        """
        return self.remove_role_in_user(user_id=user_id, role_id=role_id, atomic=atomic)

    def remove_all_roles_in_user(self, user_id: int):
        """Removes all relations with roles. Does not eliminate users and roles.

        Parameters
        ----------
        user_id : int
            ID of the user

        Returns
        -------
        True -> Success | False -> Failure
        """
        try:
            if user_id > max_id_reserved:
                roles = self.session.query(User).filter_by(id=user_id).first().roles
                for role in roles:
                    self.remove_role_in_user(user_id=user_id, role_id=role.id, atomic=False)
                self.session.commit()
                return True
        except (IntegrityError, TypeError):
            self.session.rollback()
            return False

    def remove_all_users_in_role(self, role_id: int):
        """Clone of the previous function.

        Parameters
        ----------
        role_id : str
            ID of the role

        Returns
        -------
        True -> Success | False -> Failure
        """
        try:
            if int(role_id) > max_id_reserved:
                users = self.session.query(Roles).filter_by(id=role_id).first().users
                for user in users:
                    if self.remove_user_in_role(user_id=user.id, role_id=role_id, atomic=False) is not True:
                        return SecurityError.RELATIONSHIP_ERROR
                self.session.commit()
                return True
        except (IntegrityError, TypeError):
            self.session.rollback()
            return False

    def replace_user_role(self, user_id: int, actual_role_id: int, new_role_id: int, position: int = -1):
        """Replace one existing relationship with another one.

        Parameters
        ----------
        user_id : int
            ID of the user
        actual_role_id : int
            ID of the role
        new_role_id : int
            ID of the new role
        position : int
            Order to be applied in case of multiples roles in the same user

        Returns
        -------
        True -> Success | False -> Failure
        """
        if user_id > max_id_reserved and self.exist_user_role(user_id=user_id, role_id=actual_role_id) and \
                self.session.query(Roles).filter_by(id=new_role_id).first() is not None:
            if self.remove_role_in_user(user_id=user_id, role_id=actual_role_id, atomic=False) is not True or \
                    self.add_user_to_role(user_id=user_id, role_id=new_role_id, position=position,
                                          atomic=False) is not True:
                return SecurityError.RELATIONSHIP_ERROR
            self.session.commit()
            return True

        return False


class RolesPoliciesManager:
    """
    This class is the manager of the relationship between the roles and the policies, this class provided
    all the methods needed for the roles-policies administration.
    """

    def __init__(self, session=None):
        self.session = session or sessionmaker(bind=create_engine(f"sqlite:///{_db_file}", echo=False))()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.session.close()

    def add_policy_to_role(self, role_id: int, policy_id: int, position: int = None,
                           created_at: datetime = get_utc_now(), force_admin: bool = False, atomic: bool = True) -> \
            Union[bool, SecurityError]:
        """Add a relation between one specified policy and one specified role

        Parameters
        ----------
        role_id : int
            ID of the role
        policy_id : int
            ID of the policy
        position : int
            Order to be applied in case of multiples roles in the same user
        force_admin : bool
            By default, changing an administrator roles is not allowed. If True, it will be applied to admin roles too
        atomic : bool
            This parameter indicates if the operation is atomic. If this function is called within
            a loop or a function composed of several operations, atomicity cannot be guaranteed.
            And it must be the most external function that ensures it

        Returns
        -------
        bool
            True -> Success | False -> Failure | Role not found | Policy not found | Existing relationship
        """

        def check_max_level(role_id_level):
            return max([r.level for r in self.session.query(RolesPolicies).filter_by(role_id=role_id_level).all()])

        try:
            # Create a role-policy relationship if both exist
            if int(role_id) > max_id_reserved or force_admin:
                role = self.session.query(Roles).filter_by(id=role_id).first()
                if role is None:
                    return SecurityError.ROLE_NOT_EXIST
                policy = self.session.query(Policies).filter_by(id=policy_id).first()
                if policy is None:
                    return SecurityError.POLICY_NOT_EXIST
                if position is not None or self.session.query(
                        RolesPolicies).filter_by(role_id=role_id, policy_id=policy_id).first() is None:
                    if position is not None and \
                            self.session.query(RolesPolicies).filter_by(role_id=role_id, level=position).first() and \
                            self.session.query(RolesPolicies).filter_by(role_id=role_id,
                                                                        policy_id=policy_id).first() is None:
                        role_policies = [row for row in self.session.query(
                            RolesPolicies).filter(RolesPolicies.role_id == role_id, RolesPolicies.level >= position
                                                  ).order_by(RolesPolicies.level).all()]
                        new_level = position
                        for relation in role_policies:
                            relation.level = new_level + 1
                            new_level += 1

                    role.policies.append(policy)
                    role_policy = self.session.query(RolesPolicies).filter_by(role_id=role_id,
                                                                              policy_id=policy_id).first()
                    if position is None or position > check_max_level(role_id) + 1:
                        position = len(role.get_policies()) - 1
                    else:
                        max_position = max([row.level for row in self.session.query(RolesPolicies).filter_by(
                            role_id=role_id).all()])
                        if max_position == 0 and len(list(role.policies)) - 1 == 0:
                            position = 0
                        elif position > max_position + 1:
                            position = max_position + 1
                    role_policy.level = position
                    role_policy.created_at = created_at

                    atomic and self.session.commit()
                    return True
                else:
                    return SecurityError.ALREADY_EXIST
            return SecurityError.ADMIN_RESOURCES
        except IntegrityError:
            self.session.rollback()
            return SecurityError.INVALID

    def add_role_to_policy(self, policy_id: int, role_id: int, position: int = None, force_admin: bool = False,
                           atomic: bool = True):
        """Clone of the previous function

        Parameters
        ----------
        role_id : int
            ID of the role
        policy_id : int
            ID of the policy
        position : int
            Order to be applied in case of multiples roles in the same user
        force_admin : bool
            By default, changing an administrator roles is not allowed. If True, it will be applied to admin roles too
        atomic : bool
            This parameter indicates if the operation is atomic. If this function is called within
            a loop or a function composed of several operations, atomicity cannot be guaranteed.
            And it must be the most external function that ensures it

        Returns
        -------
        bool
            True -> Success | False -> Failure | Role not found | Policy not found | Existing relationship
        """
        return self.add_policy_to_role(role_id=role_id, policy_id=policy_id, position=position,
                                       force_admin=force_admin, atomic=atomic)

    def get_all_policies_from_role(self, role_id):
        """Get all the policies related with the specified role

        Parameters
        ----------
        role_id : int
            ID of the role

        Returns
        -------
        List of policies related with the role -> Success | False -> Failure
        """
        try:
            role_policies = self.session.query(RolesPolicies).filter_by(role_id=role_id).order_by(
                RolesPolicies.level).all()
            policies = list()
            for relation in role_policies:
                policy = self.session.query(Policies).filter_by(id=relation.policy_id).first()
                if policy:
                    policies.append(policy)
            return policies
        except (IntegrityError, AttributeError):
            self.session.rollback()
            return False

    def get_all_roles_from_policy(self, policy_id: int):
        """Get all the roles related with the specified policy

        Parameters
        ----------
        policy_id : int
            ID of the policy

        Returns
        -------
        List of roles related with the policy -> Success | False -> Failure
        """
        try:
            policy = self.session.query(Policies).filter_by(id=policy_id).first()
            roles = policy.roles
            return roles
        except (IntegrityError, AttributeError):
            self.session.rollback()
            return False

    def exist_role_policy(self, role_id: int, policy_id: int):
        """Check if the relationship role-policy exist

        Parameters
        ----------
        role_id : int
            ID of the role
        policy_id : int
            ID of the policy

        Returns
        -------
        True -> Existent relationship | False -> Failure | Role not exist
        """
        try:
            role = self.session.query(Roles).filter_by(id=role_id).first()
            if role is None:
                return SecurityError.ROLE_NOT_EXIST
            policy = self.session.query(Policies).filter_by(id=policy_id).first()
            if policy is None:
                return SecurityError.POLICY_NOT_EXIST
            policy = role.policies.filter_by(id=policy_id).first()
            if policy is not None:
                return True
            return False
        except IntegrityError:
            self.session.rollback()
            return False

    def exist_policy_role(self, policy_id: int, role_id: int):
        """Check if the relationship role-policy exist

        Parameters
        ----------
        policy_id : int
            ID of the policy
        role_id : int
            ID of the role

        Returns
        -------
        True -> Existent relationship | False -> Failure | Policy not exist
        """
        return self.exist_role_policy(role_id, policy_id)

    def remove_policy_in_role(self, role_id: int, policy_id: int, atomic: bool = True):
        """Remove a role-policy relationship if both exist. Does not eliminate role and policy

        Parameters
        ----------
        role_id : int
            ID of the role
        policy_id : int
            ID of the policy
        atomic : bool
            This parameter indicates if the operation is atomic. If this function is called within
            a loop or a function composed of several operations, atomicity cannot be guaranteed.
            And it must be the most external function that ensures it

        Returns
        -------
        True -> Success | False -> Failure | Role not exist | Policy not exist | Non-existent relationship
        """
        try:
            if int(role_id) > max_id_reserved:  # Administrator
                role = self.session.query(Roles).filter_by(id=role_id).first()
                if role is None:
                    return SecurityError.ROLE_NOT_EXIST
                policy = self.session.query(Policies).filter_by(id=policy_id).first()
                if policy is None:
                    return SecurityError.POLICY_NOT_EXIST

                role_policy = self.session.query(RolesPolicies).filter_by(role_id=role_id,
                                                                          policy_id=policy_id).first()

                if role_policy is not None:
                    role = self.session.query(Roles).get(role_id)
                    policy = self.session.query(Policies).get(policy_id)
                    role.policies.remove(policy)

                    # Update position value
                    relationships_to_update = [row for row in self.session.query(
                        RolesPolicies).filter(RolesPolicies.role_id == role_id, RolesPolicies.level >= role_policy.level
                                              )]

                    for relation in relationships_to_update:
                        relation.level -= 1

                    atomic and self.session.commit()
                    return True
                else:
                    return SecurityError.INVALID
            return SecurityError.ADMIN_RESOURCES
        except IntegrityError:
            self.session.rollback()
            return SecurityError.INVALID

    def remove_role_in_policy(self, role_id: int, policy_id: int, atomic: bool = True):
        """Clone of the previous function

        Parameters
        ----------
        role_id : int
            ID of the role
        policy_id : int
            ID of the policy
        atomic : bool
            This parameter indicates if the operation is atomic. If this function is called within
            a loop or a function composed of several operations, atomicity cannot be guaranteed.
            And it must be the most external function that ensures it

        Returns
        -------
        True -> Success | False -> Failure | Role not exist | Policy not exist | Non-existent relationship
        """
        return self.remove_policy_in_role(role_id=role_id, policy_id=policy_id, atomic=atomic)

    def remove_all_policies_in_role(self, role_id: int):
        """Removes all relations with policies. Does not eliminate roles and policies

        Parameters
        ----------
        role_id : int
            ID of the role

        Returns
        -------
        True -> Success | False -> Failure
        """
        try:
            if int(role_id) > max_id_reserved:
                policies = self.session.query(Roles).filter_by(id=role_id).first().policies
                for policy in policies:
                    if self.remove_policy_in_role(role_id=role_id, policy_id=policy.id, atomic=False) is not True:
                        return SecurityError.RELATIONSHIP_ERROR
                self.session.commit()
                return True
        except (IntegrityError, TypeError):
            self.session.rollback()
            return False

    def remove_all_roles_in_policy(self, policy_id: int):
        """Removes all relations with roles. Does not eliminate roles and policies

        Parameters
        ----------
        policy_id : int
            ID of the policy

        Returns
        -------
        True -> Success | False -> Failure
        """
        try:
            if int(policy_id) > max_id_reserved:
                roles = self.session.query(Policies).filter_by(id=policy_id).first().roles
                for rol in roles:
                    self.remove_policy_in_role(role_id=rol.id, policy_id=policy_id, atomic=False)
                self.session.commit()
                return True
        except (IntegrityError, TypeError):
            self.session.rollback()
            return False

    def replace_role_policy(self, role_id: int, current_policy_id: int, new_policy_id: int):
        """Replace one existing relationship with another one

        Parameters
        ----------
        role_id : int
            ID of the role
        current_policy_id : int
            Current ID of the policy
        new_policy_id : int
            New ID for the specified policy id

        Returns
        -------
        True -> Success | False -> Failure
        """
        if int(role_id) > max_id_reserved and \
                self.exist_role_policy(role_id=role_id, policy_id=current_policy_id) and \
                self.session.query(Policies).filter_by(id=new_policy_id).first() is not None:
            if self.remove_policy_in_role(role_id=role_id, policy_id=current_policy_id, atomic=False) is not True or \
                    self.add_policy_to_role(role_id=role_id, policy_id=new_policy_id, atomic=False) is not True:
                return SecurityError.RELATIONSHIP_ERROR
            self.session.commit()
            return True

        return False


class RolesRulesManager:
    """
    This class is the manager of the relationships between the roles and the rules. This class provides
    all the methods needed for the roles-rules administration.
    """

    def __init__(self, session=None):
        self.session = session or sessionmaker(bind=create_engine(f"sqlite:///{_db_file}", echo=False))()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.session.close()

    def add_rule_to_role(self, rule_id: int, role_id: int, position: int = None, created_at: datetime = get_utc_now(),
                         atomic: bool = True, force_admin: bool = False) -> Union[bool, SecurityError]:
        """Add a relation between one specified role and one specified rule.

        Parameters
        ----------
        rule_id : int
            ID of the rule
        role_id : int
            ID of the role
        atomic : bool
            This parameter indicates if the operation is atomic. If this function is called within
            a loop or a function composed of several operations, atomicity cannot be guaranteed.
            And it must be the most external function that ensures it
        force_admin : bool
            By default, changing an administrator roles is not allowed. If True, it will be applied to admin roles too

        Returns
        -------
        True -> Success | False -> Failure | Role not found | Rule not found | Existing relationship
        """
        try:
            # Create a rule-role relationship if both exist
            if int(rule_id) > max_id_reserved or force_admin:
                rule = self.session.query(Rules).filter_by(id=rule_id).first()
                if rule is None:
                    return SecurityError.RULE_NOT_EXIST
                role = self.session.query(Roles).filter_by(id=role_id).first()
                if role is None:
                    return SecurityError.ROLE_NOT_EXIST

                if self.session.query(RolesRules).filter_by(rule_id=rule_id, role_id=role_id).first() is None:
                    role.rules.append(rule)
                    role_rule = self.session.query(RolesRules).filter_by(rule_id=rule_id, role_id=role_id).first()
                    role_rule.created_at = created_at
                    atomic and self.session.commit()
                    return True
                else:
                    return SecurityError.ALREADY_EXIST
            return SecurityError.ADMIN_RESOURCES
        except (IntegrityError, InvalidRequestError):
            self.session.rollback()
            return SecurityError.INVALID

    def get_all_rules_from_role(self, role_id: int):
        """Get all the rules related to the specified role.

        Parameters
        ----------
        role_id : int
            ID of the role

        Returns
        -------
            List of rules related with the role -> Success | False -> Failure
        """
        try:
            rule_roles = self.session.query(RolesRules).filter_by(role_id=role_id).order_by(RolesRules.id).all()
            rules = list()
            for relation in rule_roles:
                rules.append(self.session.query(Rules).filter_by(id=relation.rule_id).first())
            return rules
        except (IntegrityError, AttributeError):
            self.session.rollback()
            return False

    def get_all_roles_from_rule(self, rule_id: int):
        """Get all the roles related to the specified rule.

        Parameters
        ----------
        rule_id : int
            ID of the rule

        Returns
        -------
            List of roles related with the rule -> Success | False -> Failure
        """
        try:
            role_rules = self.session.query(RolesRules).filter_by(rule_id=rule_id).order_by(RolesRules.id).all()
            roles = list()
            for relation in role_rules:
                roles.append(self.session.query(Roles).filter_by(id=relation.role_id).first())
            return roles
        except (IntegrityError, AttributeError):
            self.session.rollback()
            return False

    def exist_role_rule(self, role_id: int, rule_id: int):
        """Check if the role-rule relationship exists.

        Parameters
        ----------
        role_id : int
            ID of the role
        rule_id : int
            ID of the rule

        Returns
        -------
        True -> Existent relationship | False -> Failure | Rule not exists | Role not exists
        """
        try:
            rule = self.session.query(Rules).filter_by(id=rule_id).first()
            if rule is None:
                return SecurityError.RULE_NOT_EXIST
            role = self.session.query(Roles).filter_by(id=role_id).first()
            if role is None:
                return SecurityError.ROLE_NOT_EXIST
            match = role.rules.filter_by(id=rule_id).first()
            if match is not None:
                return True
            return False
        except IntegrityError:
            self.session.rollback()
            return False

    def remove_rule_in_role(self, rule_id: int, role_id: int, atomic: bool = True):
        """Remove a role-rule relationship if both exists. This does not delete the objects.

        Parameters
        ----------
        rule_id : int
            ID of the rule
        role_id : int
            ID of the role
        atomic : bool
            This parameter indicates if the operation is atomic. If this function is called within
            a loop or a function composed of several operations, atomicity cannot be guaranteed.
            And it must be the most external function that ensures it

        Returns
        -------
        True -> Success | False -> Failure | Role not exists | Rule not exist s| Non-existent relationship
        """
        try:
            if int(rule_id) > max_id_reserved:  # Required rule
                rule = self.session.query(Rules).filter_by(id=rule_id).first()
                if rule is None:
                    return SecurityError.RULE_NOT_EXIST
                role = self.session.query(Roles).filter_by(id=role_id).first()
                if role is None:
                    return SecurityError.ROLE_NOT_EXIST
                if self.session.query(RolesRules).filter_by(rule_id=rule_id, role_id=role_id).first() is not None:
                    rule = self.session.query(Rules).get(rule_id)
                    role = self.session.query(Roles).get(role_id)
                    rule.roles.remove(role)
                    atomic and self.session.commit()
                    return True
                else:
                    return SecurityError.INVALID
            return SecurityError.ADMIN_RESOURCES
        except IntegrityError:
            self.session.rollback()
            return SecurityError.INVALID

    def remove_role_in_rule(self, rule_id: int, role_id: int, atomic: bool = True):
        """Remove a role-rule relationship if both exists. This does not delete the objects.

        Parameters
        ----------
        rule_id : int
            ID of the rule
        role_id : int
            ID of the role
        atomic : bool
            This parameter indicates if the operation is atomic. If this function is called within
            a loop or a function composed of several operations, atomicity cannot be guaranteed.
            And it must be the most external function that ensures it

        Returns
        -------
        True -> Success | False -> Failure | Role not exists | Rule not exist s| Non-existent relationship
        """
        return self.remove_rule_in_role(rule_id=rule_id, role_id=role_id, atomic=atomic)

    def remove_all_roles_in_rule(self, rule_id: int):
        """Remove all relations between a rule and its roles. This does not delete the objects.

        Parameters
        ----------
        rule_id : int
            ID of the rule

        Returns
        -------
        True -> Success | False -> Failure
        """
        try:
            if int(rule_id) > max_id_reserved:
                self.session.query(Rules).filter_by(id=rule_id).first().roles = list()
                self.session.commit()
                return True
            return SecurityError.ADMIN_RESOURCES
        except (IntegrityError, TypeError):
            self.session.rollback()
            return False

    def remove_all_rules_in_role(self, role_id: int):
        """Remove all relations between a role and its rules. This does not delete the objects.

        Parameters
        ----------
        role_id : int
            ID of the role

        Returns
        -------
        True -> Success | False -> Failure
        """
        try:
            if int(role_id) > max_id_reserved:
                self.session.query(Roles).filter_by(id=role_id).first().rules = list()
                self.session.commit()
                return True
        except (IntegrityError, TypeError):
            self.session.rollback()
            return False

    def replace_rule_role(self, rule_id: int, current_role_id: int, new_role_id: int):
        """Replace one existing role_rule relationship with another one.

        Parameters
        ----------
        rule_id : int
            ID of the rule
        current_role_id : int
            Current ID of the role
        new_role_id : int
            New role ID

        Returns
        -------
        True -> Success | False -> Failure
        """
        if current_role_id > max_id_reserved and self.exist_role_rule(
                rule_id=rule_id,
                role_id=current_role_id) \
                and self.session.query(Roles).filter_by(id=new_role_id).first() is not None:
            if self.remove_role_in_rule(rule_id=rule_id, role_id=current_role_id, atomic=False) is not True or \
                    self.add_rule_to_role(rule_id=rule_id, role_id=new_role_id, atomic=False) is not True:
                return SecurityError.RELATIONSHIP_ERROR

            return True

        return False


class DatabaseManager:
    def __init__(self):
        self.engines = {}
        self.sessions = {}

    def close_sessions(self):
        for session in self.sessions:
            self.sessions[session].close()

        for engine in self.engines:
            self.engines[engine].dispose()

    def connect(self, database: str):
        self.engines[database] = create_engine(f"sqlite:///{database}", echo=False)
        self.sessions[database] = sessionmaker(bind=self.engines[database])()

    def create_database(self, database: str):
        # This is the actual sqlite database creation
        _Base.metadata.create_all(self.engines[database])

    def get_database_version(self, database: str):
        return str(self.sessions[database].execute("pragma user_version").first()[0])

    def insert_default_resources(self, database: str):
        default_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'default')

        # Create default users if they don't exist yet
        with open(os.path.join(default_path, "users.yaml"), 'r') as stream:
            default_users = yaml.safe_load(stream)

            with AuthenticationManager(self.sessions[database]) as auth:
                for d_username, payload in default_users[next(iter(default_users))].items():
                    auth.add_user(username=d_username, password=payload['password'], resource_type=ResourceType.DEFAULT,
                                  check_default=False)
                    auth.edit_run_as(user_id=auth.get_user(username=d_username)['id'],
                                     allow_run_as=payload['allow_run_as'])

        # Create default roles if they don't exist yet
        with open(os.path.join(default_path, "roles.yaml"), 'r') as stream:
            default_roles = yaml.safe_load(stream)

            with RolesManager(self.sessions[database]) as rm:
                for d_role_name, payload in default_roles[next(iter(default_roles))].items():
                    rm.add_role(name=d_role_name, resource_type=ResourceType.DEFAULT, check_default=False)

        with open(os.path.join(default_path, 'rules.yaml'), 'r') as stream:
            default_rules = yaml.safe_load(stream)

            with RulesManager(self.sessions[database]) as rum:
                for d_rule_name, payload in default_rules[next(iter(default_rules))].items():
                    rum.add_rule(name=d_rule_name, rule=payload['rule'], resource_type=ResourceType.DEFAULT,
                                 check_default=False)

        # Create default policies if they don't exist yet
        with open(os.path.join(default_path, "policies.yaml"), 'r') as stream:
            default_policies = yaml.safe_load(stream)

            with PoliciesManager(self.sessions[database]) as pm:
                for d_policy_name, payload in default_policies[next(iter(default_policies))].items():
                    for name, policy in payload['policies'].items():
                        policy_name = f'{d_policy_name}_{name}'
                        policy_result = pm.add_policy(name=policy_name, policy=policy,
                                                      resource_type=ResourceType.DEFAULT, check_default=False)
                        # Update policy if it exists
                        if policy_result == SecurityError.ALREADY_EXIST:
                            try:
                                policy_id = pm.get_policy(policy_name)['id']
                                if policy_id < max_id_reserved:
                                    pm.update_policy(policy_id=policy_id, name=policy_name, policy=policy,
                                                     resource_type=ResourceType.DEFAULT, check_default=False)
                                else:
                                    with RolesPoliciesManager(self.sessions[database]) as rpm:
                                        linked_roles = [role.id for role in
                                                        rpm.get_all_roles_from_policy(policy_id=policy_id)]
                                        new_positions = dict()
                                        for role in linked_roles:
                                            new_positions[role] = [
                                                p.id for p in rpm.get_all_policies_from_role(role_id=role)
                                            ].index(policy_id)

                                        pm.delete_policy(policy_id=policy_id)
                                        pm.add_policy(name=policy_name, policy=policy,
                                                      resource_type=ResourceType.DEFAULT, check_default=False)
                                        policy_id = pm.get_policy(policy_name)['id']
                                        for role, position in new_positions.items():
                                            rpm.add_role_to_policy(policy_id=policy_id, role_id=role, position=position,
                                                                   force_admin=True)

                            except (KeyError, TypeError):
                                pass

        # Create the relationships
        with open(os.path.join(default_path, "relationships.yaml"), 'r') as stream:
            default_relationships = yaml.safe_load(stream)

            # User-Roles relationships
            with UserRolesManager(self.sessions[database]) as urm:
                for d_username, payload in default_relationships[next(iter(default_relationships))]['users'].items():
                    with AuthenticationManager(self.sessions[database]) as am:
                        d_user_id = am.get_user(username=d_username)['id']
                    for d_role_name in payload['role_ids']:
                        urm.add_role_to_user(user_id=d_user_id, role_id=rm.get_role(name=d_role_name)['id'],
                                             force_admin=True)

            # Role-Policies relationships
            with RolesPoliciesManager(self.sessions[database]) as rpm:
                for d_role_name, payload in default_relationships[next(iter(default_relationships))]['roles'].items():
                    for d_policy_name in payload['policy_ids']:
                        for sub_name in \
                                default_policies[next(iter(default_policies))][d_policy_name]['policies'].keys():
                            rpm.add_policy_to_role(role_id=rm.get_role(name=d_role_name)['id'],
                                                   policy_id=pm.get_policy(name=f'{d_policy_name}_{sub_name}')['id'],
                                                   force_admin=True)

            # Role-Rules relationships
            with RolesRulesManager(self.sessions[database]) as rrum:
                for d_role_name, payload in default_relationships[next(iter(default_relationships))]['roles'].items():
                    for d_rule_name in payload['rule_ids']:
                        rrum.add_rule_to_role(role_id=rm.get_role(name=d_role_name)['id'],
                                              rule_id=rum.get_rule_by_name(d_rule_name)['id'], force_admin=True)

    @staticmethod
    def get_table(session, table: object):
        try:
            # Try to use the current table schema
            session.query(table).first()
            return session.query(table)
        except OperationalError:
            # Return an old schema without the new columns
            return session.query(table).with_entities(*[column for column in table.__table__.columns
                                                        if column.key not in _new_columns])

    def migrate_data(self, source, target, from_id: int = None, to_id: int = None, resource_type: ResourceType = None):
        """Get the resources from the `source` database filtering by IDs and insert them into the `target` database.
        This function will adapt the relationship between problematic resources if needed."""

        def get_data(table, col_a, col_b=None):
            """Get the resources from the given table filtering up to 2 columns by the 'from_id' and 'to_id'
            parameters."""
            result = []
            try:
                if from_id and to_id:
                    condition = or_(col_a.between(from_id, to_id),
                                    col_b.between(from_id, to_id)) if col_b else col_a.between(from_id, to_id)
                elif from_id:
                    condition = or_(col_a >= from_id, col_b >= from_id) if col_b else col_a >= from_id
                elif to_id:
                    condition = or_(col_a <= from_id, col_b <= from_id) if col_b else col_a <= from_id

                result = [resource for resource in
                          self.get_table(self.sessions[source], table).filter(condition).order_by(col_a).all()]
            except OperationalError:
                pass

            return result

        old_users = get_data(User, User.id)
        with AuthenticationManager(self.sessions[target]) as auth_manager:
            for user in old_users:
                auth_manager.add_user(username=user.username,
                                      password=user.password,
                                      created_at=user.created_at,
                                      user_id=user.id,
                                      hash_password=True,
                                      resource_type=resource_type,
                                      check_default=False)
                auth_manager.edit_run_as(user_id=user.id, allow_run_as=user.allow_run_as)

        old_roles = get_data(Roles, Roles.id)
        with RolesManager(self.sessions[target]) as role_manager:
            for role in old_roles:
                role_manager.add_role(name=role.name,
                                      created_at=role.created_at,
                                      role_id=role.id,
                                      resource_type=resource_type,
                                      check_default=False)

        old_rules = get_data(Rules, Rules.id)
        with RulesManager(self.sessions[target]) as rule_manager:
            for rule in old_rules:
                rule_manager.add_rule(name=rule.name,
                                      rule=json.loads(rule.rule),
                                      created_at=rule.created_at,
                                      rule_id=rule.id,
                                      resource_type=resource_type,
                                      check_default=False)

        old_policies = get_data(Policies, Policies.id)
        with PoliciesManager(self.sessions[target]) as policy_manager:
            for policy in old_policies:
                status = policy_manager.add_policy(name=policy.name,
                                                   policy=json.loads(policy.policy),
                                                   created_at=policy.created_at,
                                                   policy_id=policy.id,
                                                   resource_type=resource_type,
                                                   check_default=False)
                # If the user's policy has the same body as an existing default policy it won't be inserted and its
                # role-policy relationships will be linked to that default policy instead to replace it.
                if status == SecurityError.ALREADY_EXIST or status == SecurityError.CONSTRAINT_ERROR:
                    roles_policies = self.get_table(source, RolesPolicies).filter(
                        RolesPolicies.policy_id == policy.id).order_by(RolesPolicies.id.asc()).all()
                    new_policy_id = self.sessions[target].query(Policies).filter_by(
                        policy=str(policy.policy)).first().id
                    with RolesPoliciesManager(self.sessions[target]) as role_policy_manager:
                        for role_policy in roles_policies:
                            role_policy_manager.add_policy_to_role(role_id=role_policy.role_id,
                                                                   policy_id=new_policy_id,
                                                                   position=role_policy.level,
                                                                   created_at=role_policy.created_at,
                                                                   force_admin=True)

        old_user_roles = get_data(UserRoles, UserRoles.user_id, UserRoles.role_id)
        with UserRolesManager(self.sessions[target]) as user_role_manager:
            for user_role in old_user_roles:
                user_id = user_role.user_id
                role_id = user_role.role_id
                try:
                    # Look for the ID of a default resource from the old database in the new database using its name
                    # This allows us to keep the relationship if the related default resource now has a different id
                    if int(user_id) <= max_id_reserved:
                        user_name = self.get_table(self.sessions[source], User).filter(
                            User.id == user_id).first().username
                        user_id = AuthenticationManager(self.sessions[target]).get_user(username=user_name)['id']

                    if int(role_id) <= max_id_reserved:
                        role_name = self.get_table(self.sessions[source], Roles).filter(
                            Roles.id == role_id).first().name
                        role_id = RolesManager(self.sessions[target]).get_role(name=role_name)['id']

                    user_role_manager.add_role_to_user(user_id=user_id,
                                                       role_id=role_id,
                                                       position=user_role.level,
                                                       created_at=user_role.created_at,
                                                       force_admin=True)
                except TypeError:
                    # An exception will be raised if one of the resources are no longer present in any of the databases
                    # and thus the relationship won't be added to the new database.
                    pass

        # Role-Policies relationships
        old_roles_policies = get_data(RolesPolicies, RolesPolicies.role_id, RolesPolicies.policy_id)
        with RolesPoliciesManager(self.sessions[target]) as role_policy_manager:
            for role_policy in old_roles_policies:
                role_id = role_policy.role_id
                policy_id = role_policy.policy_id
                try:
                    # Look for the ID of a default resource from the old database in the new database using its name
                    # This allows us to keep the relationship if the related default resource now has a different id
                    if int(role_id) <= max_id_reserved:
                        role_name = self.get_table(self.sessions[source], Roles).filter(
                            Roles.id == role_id).first().name
                        role_id = RolesManager(self.sessions[target]).get_role(name=role_name)['id']

                    if int(policy_id) <= max_id_reserved:
                        policy_name = self.get_table(self.sessions[source], Policies).filter(
                            Policies.id == policy_id).first().name
                        policy_id = PoliciesManager(self.sessions[target]).get_policy(name=policy_name)['id']

                    role_policy_manager.add_policy_to_role(role_id=role_id,
                                                           policy_id=policy_id,
                                                           position=role_policy.level,
                                                           created_at=role_policy.created_at,
                                                           force_admin=True)
                except TypeError:
                    # An exception will be raised if one of the resources are no longer present in any of the databases
                    # and thus the relationship won't be added to the new database.
                    pass

        # Role-Rules relationships
        old_roles_rules = get_data(RolesRules, RolesRules.role_id, RolesRules.rule_id)
        with RolesRulesManager(self.sessions[target]) as role_rule_manager:
            for role_rule in old_roles_rules:
                role_id = role_rule.role_id
                rule_id = role_rule.rule_id
                try:
                    # Look for the ID of a default resource from the old database in the new database using its name
                    # This allows us to keep the relationship if the related default resource now has a different id
                    if int(role_id) <= max_id_reserved:
                        role_name = self.get_table(self.sessions[source], Roles).filter(
                            Roles.id == role_id).first().name
                        role_id = RolesManager(self.sessions[target]).get_role(name=role_name)['id']

                    if int(rule_id) <= max_id_reserved:
                        rule_name = self.get_table(self.sessions[source], Rules).filter(
                            Rules.id == rule_id).first().name
                        rule_id = RulesManager(self.sessions[target]).get_rule_by_name(rule_name=rule_name)['id']

                    role_rule_manager.add_rule_to_role(role_id=role_id,
                                                       rule_id=rule_id,
                                                       created_at=role_rule.created_at,
                                                       force_admin=True)
                except TypeError:
                    # An exception will be raised if one of the resources are no longer present in any of the databases
                    # and thus the relationship won't be added to the new database.
                    pass

    def rollback(self, database):
        """Abort any pending change for the current session."""
        self.sessions[database].rollback()

    def set_database_version(self, database, version):
        """Set the new value for the database version."""
        self.sessions[database].execute(f'pragma user_version={version}')


def check_database_integrity():
    def _set_permissions_and_ownership(database: str):
        chown(_db_file, wazuh_uid(), wazuh_gid())
        os.chmod(_db_file, 0o640)

    logger = logging.getLogger("wazuh-api")

    try:
        logger.info("Checking RBAC database integrity...")

        if os.path.exists(_db_file):
            # If db exists, fix permissions and ownership and connect to it
            logger.info(f"{_db_file} file was detected")
            _set_permissions_and_ownership(_db_file)
            db_manager.connect(_db_file)
            current_version = int(db_manager.get_database_version(_db_file))
            expected_version = int(get_api_revision())

            # Check if an upgrade is required
            if current_version < expected_version:
                logger.info("RBAC database migration required. "
                            f"Current version is {current_version} but it should be {expected_version}. "
                            f"Upgrading RBAC database to {expected_version} version")
                # Remove tmp database if present
                os.path.exists(_db_file_tmp) and os.remove(_db_file_tmp)

                # Create new tmp database and populate it with default resources
                db_manager.connect(_db_file_tmp)
                db_manager.create_database(_db_file_tmp)
                _set_permissions_and_ownership(_db_file_tmp)
                db_manager.insert_default_resources(_db_file_tmp)

                # Migrate data from old database
                db_manager.migrate_data(source=_db_file, target=_db_file_tmp, from_id=cloud_reserved_range,
                                        to_id=max_id_reserved, resource_type=ResourceType.PROTECTED)
                db_manager.migrate_data(source=_db_file, target=_db_file_tmp, from_id=max_id_reserved + 1,
                                        resource_type=ResourceType.USER)

                # Apply changes and replace database
                db_manager.set_database_version(_db_file_tmp, str(expected_version))
                db_manager.close_sessions()
                safe_move(_db_file_tmp, _db_file,
                          ownership=(wazuh_uid(), wazuh_gid()),
                          permissions=0o640)
                logger.info(f"{_db_file} database upgraded successfully")

        # If database does not exist it means this is a fresh installation and must be created properly
        else:
            logger.info(f"RBAC database not found. Creating a new one")
            db_manager.connect(_db_file)
            db_manager.create_database(_db_file)
            _set_permissions_and_ownership(_db_file)
            db_manager.insert_default_resources(_db_file)
            db_manager.set_database_version(_db_file, get_api_revision())
            db_manager.close_sessions()
            logger.info(f"{_db_file} database created successfully")
    except ValueError:
        logger.error("Error retrieving the current Wazuh revision. Aborting database integrity check")
        db_manager.close_sessions()
    except Exception as e:
        logger.error("Error during the database migration. Restoring the previous database file")
        logger.error(f"Error details: {str(e)}")
        db_manager.close_sessions()
    else:
        logger.info("RBAC database integrity check finished successfully")
    finally:
        # Remove tmp database if present
        os.path.exists(_db_file_tmp) and os.remove(_db_file_tmp)


db_manager = DatabaseManager()
