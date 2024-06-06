import logging
import re
import ast
import jsonschema

from common.djangoapps.student.roles import GlobalStaff
from social_django.models import UserSocialAuth

log = logging.getLogger(__name__)

def serialize_user_info(user, user_social_auths=None):
    """
    Helper method to serialize resulting in user_info_object
    based on passed in django models
    """
    user_info = {
        'username': user.username,
        'email': user.email,
        'sso_list': [],
    }
    if user_social_auths:
        for user_social_auth in user_social_auths:
            user_info['sso_list'].append({
                "provider": user_social_auth.provider,
                'uid': user_social_auth.uid,
            })
    return user_info

def is_enrollment_allowed(user, course_id, course_overview):
    """ Check whether user is allowed to enroll in a course """

    def eval_enrollment_allow_or_block_list(course_id, enrollment_allow_or_block_list):
        """ Validate the input of allowlist or blocklist """
        try:
            list_dict = ast.literal_eval(enrollment_allow_or_block_list)

            schema = {
                "type" : "object",
                "patternProperties" : {
                    "^.*$" : {
                        "type" : "array",
                        "items" : { "type": "string" }
                    },
                },
            }

            jsonschema.validate(list_dict, schema=schema)

            return list_dict
        except Exception:
            log.exception('Enrollment allowlist or blocklist is invalid, the list will not be applied: course="%s"', course_id)
            return None

    def extract_sign_in_info(user_info):
        """ Extract and transform the sso list of a user """
        edx_provider_name = "openedx"

        def transform_sso_list(sso_list):
            provider = sso_list["provider"]
            uid = sso_list["uid"]

            if provider == "tpa-saml":
                uid_keys = uid.split(":")
                return { "provider": uid_keys[0], "match_key": uid_keys[1] }

            return { "provider": provider, "match_key": uid }

        sso_list = user_info["sso_list"]

        try:
            sign_in_info = list(map(transform_sso_list, sso_list))
            sign_in_info.append({ "provider": edx_provider_name, "match_key": user_info["email"] })
            return sign_in_info

        except Exception:
            log.exception('Failed to extract sso list from user, user="%s"', user_info.username)
            return { "provider": edx_provider_name, "match_key": user_info["email"] }

    def is_matched(provider, regexes, sign_in_info):
        profiles = sign_in_info if provider == "*" else [info for info in sign_in_info if re.search(provider, info["provider"], re.IGNORECASE)]
        match_keys = [profile["match_key"] for profile in profiles]

        for regex in regexes:
            if any(match_key for match_key in match_keys if re.search(regex, match_key, re.IGNORECASE)): return True
        return False

    try:
        if GlobalStaff().has_user(user): return true

        user_social_auths = UserSocialAuth.objects.filter(user=user)
        user_info = serialize_user_info(user, user_social_auths)
        sign_in_info = extract_sign_in_info(user_info)

        enrollment_allowlist = eval_enrollment_allow_or_block_list(course_id, course_overview.enrollment_allowlist) if course_overview.enrollment_allowlist is not None else None
        enrollment_blocklist = eval_enrollment_allow_or_block_list(course_id, course_overview.enrollment_blocklist) if course_overview.enrollment_blocklist is not None else None

        if enrollment_blocklist and enrollment_blocklist is not None:
            for provider, regexes in enrollment_blocklist.items():
                if is_matched(provider, regexes, sign_in_info): return False

        if enrollment_allowlist and enrollment_allowlist is not None:
            for provider, regexes in enrollment_allowlist.items():
                if is_matched(provider, regexes, sign_in_info): return True
            return False

        return True
    except Exception:
        log.exception('Failed to handle enrollment checking, user="%s"', user.username)
        return True
