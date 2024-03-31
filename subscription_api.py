# Decompiled with PyLingual (https://pylingual.io)
# Internal filename: subscription_api.py
# Bytecode version: 3.8.0rc1+ (3413)
# Source timestamp: 1970-01-01 00:00:00 UTC (0)

import re
import uuid
import json
import time
import stripe
import boto3
import urllib
import hashlib
import cherrypy
import logging
import logging.config
import datetime
import requests
import traceback
from decimal import Decimal
from botocore.exceptions import ClientError
from data.data_access_factory import DataAccessFactory
from utils import passwordComplexityCheck, getRequestJson, is_valid_email_address, parse_multiline_input, Unauthenticated
from cachetools.func import ttl_cache

class SubscriptionApi(object):
    def __init__(self, config):
        self.config = config
        self._db = DataAccessFactory.createSession(config['database']['type'], config)
        self.logger = logging.getLogger('subscription_api_server')
        self.logger.info('%s initialized' % self.__class__.__name__)

    def get_stripe_products(self):
        if self._db.get_config_setting_bool('subscription', 'enforce', True):
            try:
                stripe_product_grouping_id = self._db.get_config_setting_value('subscription', 'stripe_product_grouping_id')
                stripe_api_key = self._db.get_config_setting_value('subscription', 'stripe_private_key')
                stripe.api_key = stripe_api_key
                stripe.api_version = '2019-12-03'
                products = stripe.Product.list()
                self.all_products = []
                for product in products['data']:
                    if product['active']:
                        plans = stripe.Plan.list(product=product['id'])
                        _plans = []
                        for plan in plans:
                            if plan['active'] and plan['metadata'].get('product_grouping_id') == stripe_product_grouping_id and (product['metadata'].get('product_grouping_id') == stripe_product_grouping_id):
                                _plans.append({'amount': plan['amount'], 'description': plan['metadata']['description'] if 'description' in plan['metadata'] else None, 'group_id': plan['metadata']['group_id'] if 'group_id' in plan['metadata'] else None, 'id': plan['id'], 'product_id': plan['product'], 'name': plan['nickname'], 'trial_days': plan['trial_period_days']})
                        if _plans:
                            self.all_products.append({'name': product['name'], 'id': product['id'], 'description': product['metadata'].get('description', ''), 'plans': _plans})
                self.logger.info('Fetched Stripe Products (%s)' % json.dumps(self.all_products, sort_keys=True))
            except Exception as e:
                self.logger.exception('Unable to fetch stripe products. (%s)' % e)
        return self.all_products

    @cherrypy.expose
    @Unauthenticated()
    def requestResetEmail(self):
        event = getRequestJson(cherrypy.request)
        response = {}
        recap = self.validateReCaptcha(event)
        if recap['status'] == False:
            response['error_message'] = recap['error_message'] if 'error_message' in recap else 'Unable to verify ReCaptcha'
        else:  # inserted
            if 'emailaddress' not in event or event['emailaddress'] == None or (not is_valid_email_address(event['emailaddress'])):
                response['error_message'] = 'Invalid Email Address'
            else:  # inserted
                user = cherrypy.request.db.getUser(event['emailaddress'])
                if user is None:
                    self.logger.error('Password reset email requested for non-registered address %s' % event['emailaddress'])
                else:  # inserted
                    pw_reset_token = str(uuid.uuid4())
                    user.locked = False
                    user.email_confirm_token = pw_reset_token
                    user.email_pw_reset_request_date = datetime.datetime.utcnow()
                    cherrypy.request.db.updateUser(user)
                    body = '\n                <html>\n                    <head></head>\n                    <body>\n                      <h1>Kasm Workspaces</h1>\n                      <p>A password reset has been requested for this account. Click this \n                        <a href=\'https://{}/#/reset?emailaddress={}&token={}\'>Password Rest Link </a> to reset your password.\n                      </p>\n                    </body>\n                </html>\n                '
                    self.sendEmailHTML(event['emailaddress'], 'Kasm - Password Reset Request', body.format(cherrypy.request.db.get_config_setting_value('subscription', 'app_domain'), urllib.parse.quote(event['emailaddress']), pw_reset_token))
        return json.dumps(response)

    @cherrypy.expose
    @Unauthenticated()
    def passwordReset(self):
        event = getRequestJson(cherrypy.request)
        response = {}
        recap = self.validateReCaptcha(event)
        if recap['status'] == False:
            response['error_message'] = recap['error_message'] if 'error_message' in recap else 'Unable to verify ReCaptcha'
        else:  # inserted
            if 'emailaddress' not in event or event['emailaddress'] == None or (not is_valid_email_address(event['emailaddress'])):
                response['error_message'] = 'Invalid Email Address'
            else:  # inserted
                if 'reset_token' not in event or event['reset_token'] == None:
                    response['error_message'] = 'Access Denied'
                else:  # inserted
                    if 'password' in event:
                        pwr = passwordComplexityCheck(event['password'], require_lower=False, require_upper=False, require_special=False, require_numbers=False)
                        if not pwr['status']:
                            response['error_message'] = pwr['message']
        if 'error_message' not in response:
            email_address = event['emailaddress'].strip().lower()
            user = cherrypy.request.db.getUser(email_address)
            if not user or (user.email_confirm_token and user.email_pw_reset_request_date):
                diff = Decimal(datetime.datetime.utcnow().timestamp()) - Decimal(user.email_pw_reset_request_date.timestamp())
                if diff < int(cherrypy.request.db.get_config_setting_value('subscription', 'pw_reset_token_lifetime')):
                    if event['reset_token'] == user.email_confirm_token:
                        salt = str(uuid.uuid4())
                        hashy = hashlib.sha256(event['password'].encode() + salt.encode()).hexdigest()
                        user.locked = False
                        user.pw_hash = hashy
                        user.salt = salt
                        user.email_confirm_token = None
                        user.email_pw_reset_request_date = None
                        cherrypy.request.db.updateUser(user)
                        self.logger.debug('Password successfully changed for (%s)' % user.username)
                        cherrypy.request.db.remove_all_session_tokens(user)
                    else:  # inserted
                        response['error_message'] = 'Password reset token is not valid'
                else:  # inserted
                    response['error_message'] = 'Email password reset token has expired'
            else:  # inserted
                response['error_message'] = 'Password reset token is not valid'
        if 'error_message' in response:
            logging.warning('passwordReset: {0}'.format(response['error_message']))
        else:  # inserted
            logging.info('passwordReset: Successful: {0}'.format(event['emailaddress']))
        return json.dumps(response)

    @cherrypy.expose
    @Unauthenticated()
    def cancelNewsletter(self):
        event = getRequestJson(cherrypy.request)
        response = {}
        recap = self.validateReCaptcha(event)
        if recap['status'] == False:
            response['error_message'] = recap['error_message'] if 'error_message' in recap else 'Unable to verify ReCaptcha'
        else:  # inserted
            if 'emailaddress' not in event or event['emailaddress'] == None or (not is_valid_email_address(event['emailaddress'])):
                response['error_message'] = 'Invalid Email Address'
        if 'error_message' not in response:
            newsletter = cherrypy.request.db.getNewsletter(event['emailaddress'])
            if newsletter:
                newsletter.enabled = False
                cherrypy.request.db.updateNewsletter(newsletter)
            else:  # inserted
                response['error_message'] = 'This email address is not currently subscribed to the newsletter.'
        if 'error_message' in response:
            logging.warning('cancelNewsletter: {0}: {1}'.format(response['error_message'], event))
        else:  # inserted
            logging.info('cancelNewsletter: Successful')
        return json.dumps(response)

    @cherrypy.expose
    @Unauthenticated()
    def signupNewsletter(self):
        event = getRequestJson(cherrypy.request)
        response = {}
        recap = self.validateReCaptcha(event)
        if recap['status'] == False:
            response['error_message'] = recap['error_message'] if 'error_message' in recap else 'Unable to verify ReCaptcha'
        else:  # inserted
            if 'emailaddress' not in event or event['emailaddress'] == None or (not is_valid_email_address(event['emailaddress'])):
                response['error_message'] = 'Invalid Email Address'
        if 'error_message' not in response:
            newsletter = cherrypy.request.db.getNewsletter(event['emailaddress'])
            if not newsletter:
                cherrypy.request.db.createNewsletter(event['emailaddress'], 'general')
            else:  # inserted
                if newsletter.enabled:
                    response['error_message'] = 'This email address is already registered.'
                else:  # inserted
                    newsletter.enabled = True
                    cherrypy.request.db.updateNewsletter(newsletter)
        if 'error_message' in response:
            logging.warning('signupNewsletter: {0}: {1}'.format(response['error_message'], event))
        else:  # inserted
            logging.info('signupNewsletter: Successful')
        return json.dumps(response)

    def hubSpotRegisterContact(self, event, demo_account_registration_link, demo_account_registration_href):
        headers = {}
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
        endpoint = 'https://forms.hubspot.com/uploads/form/v2/%s/%s?&' % (cherrypy.request.db.get_config_setting_value('subscription', 'hubspot_portal_id'), cherrypy.request.db.get_config_setting_value('subscription', 'hubspot_registration_form_id'))
        hs_context = json.dumps({'hutk': cherrypy.request.cookie['hubspotutk'].value if cherrypy.request.cookie.get('hubspotutk') else '', 'ipAddress': cherrypy.request.headers['X-Forwarded-For'].split(',')[0] if 'X-Forwarded-For' in cherrypy.request.headers else cherrypy.request.remote.ip, 'pageUrl': cherrypy.request.base + cherrypy.request.path_info, 'pageName': 'Create Account'})
        data = urllib.parse.urlencode({'email': event['emailaddress'], 'hs_context': hs_context, 'demo_account_registration_link': demo_account_registration_link, 'demo_account_registration_href': demo_account_registration_href})
        logging.info('Sending Hubspot Registration Request: %s' % data)
        r = requests.post(url=endpoint, data=data, headers=headers)
        if not r.ok:
            self.logger.error('Error sending Hubspot request: %s' % r.content.decode('utf-8'))

    def hubSpotRegisterContactSubscription(self, email, stripe_customer_id, stripe_plan_id, stripe_product_id, stripe_product_name, stripe_plan_nickname, stripe_enrolled):
        headers = {}
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
        endpoint = 'https://forms.hubspot.com/uploads/form/v2/%s/%s?&' % (cherrypy.request.db.get_config_setting_value('subscription', 'hubspot_portal_id'), cherrypy.request.db.get_config_setting_value('subscription', 'hubspot_subscription_form_id'))
        data = urllib.parse.urlencode({'email': email, 'stripe_customer_id': stripe_customer_id, 'stripe_plan_id': stripe_plan_id, 'stripe_product_id': stripe_product_id, 'stripe_product_name': stripe_product_name, 'stripe_plan_nickname': stripe_plan_nickname, 'stripe_enrolled': stripe_enrolled})
        logging.info('Sending Hubspot Subscription Update Request: %s' % data)
        r = requests.post(url=endpoint, data=data, headers=headers)
        if not r.ok:
            self.logger.error('Error sending Hubspot request: %s' % r.content.decode('utf-8'))

    def is_email_verified(self, address):
        self.logger.info('Verifying Email : %s' % address)
        url = 'https://mailcheck.p.rapidapi.com/'
        querystring = {'disable_test_connection': 'false', 'domain': address}
        headers = {'x-rapidapi-host': 'mailcheck.p.rapidapi.com', 'x-rapidapi-key': 'cfe41ef802msh127a4f17d978e14p168b82jsnc84bd3fbe49c'}
        response = requests.request('GET', url, headers=headers, params=querystring)
        self.logger.info('Check-Mail API response (%s)' % response.text)
        data = json.loads(response.text)
        do_block = data['block']
        if do_block:
            self.logger.warning('Block (%s) ? : (%s)' % (address, do_block))
        else:  # inserted
            self.logger.info('Block (%s) ? : (%s)' % (address, do_block))
        return not data['block']

    @staticmethod
    @ttl_cache(maxsize=500, ttl=7200)
    def check_ip_requests(ip):
        return time.time()

    @cherrypy.expose
    @Unauthenticated()
    def createAccount(self):
        event = getRequestJson(cherrypy.request)
        response = {}
        ip = cherrypy.request.headers['X-Forwarded-For'].split(',')[0] if 'X-Forwarded-For' in cherrypy.request.headers else cherrypy.request.remote.ip
        invite_code = cherrypy.request.db.config['subscription'].get('invite_code')
        recap = self.validateReCaptcha(event)
        if recap['status'] == False:
            response['error_message'] = recap['error_message'] if 'error_message' in recap else 'Unable to verify ReCaptcha'
        else:  # inserted
            if not (invite_code and invite_code.value.lower() != 'none' and ('invite' in event and event['invite'] != None and (invite_code.value == event['invite']))):
                response['error_message'] = 'Kasm is currently by invite only. Please check back soon or sign up for a news letter!'
            else:  # inserted
                if 'emailaddress' not in event or event['emailaddress'] == None or (not is_valid_email_address(event['emailaddress'])):
                    response['error_message'] = 'Invalid Email Address'
        if 'password' not in event or event['password'] == None:
            response['error_message'] = 'Please enter a password'
        else:  # inserted
            pwr = passwordComplexityCheck(event['password'], require_lower=False, require_upper=False, require_special=False, require_numbers=False)
            if not pwr['status']:
                response['error_message'] = pwr['message']
        blacklist_ok = True
        email_domain_blacklist = cherrypy.request.db.get_config_setting_value('subscription', 'email_domain_blacklist')
        if email_domain_blacklist:
            email_domain_blacklist = parse_multiline_input(email_domain_blacklist)
            if event['emailaddress'].split('@')[1] in email_domain_blacklist:
                blacklist_ok = False
                self.logger.warning('Email address (%s) is a member of the Email Domain Blacklist' % event['emailaddress'])
                response['error_message'] = 'Accounts are not allowed from this domain'
            else:  # inserted
                self.logger.debug('Email (%s) passed Email Domain Blacklist check' % event['emailaddress'])
        if blacklist_ok:
            verify_email_addresses = cherrypy.request.db.get_config_setting_bool('subscription', 'verify_email_addresses', True)
            if verify_email_addresses:
                is_verified = self.is_email_verified(event['emailaddress'].split('@')[1])
                if not is_verified:
                    self.logger.warning('Account for address %s is rejected' % event['emailaddress'])
                    response['error_message'] = 'Accounts are not allowed from this domain'
            else:  # inserted
                logging.debug('Spam email validation disabled')
        if 'error_message' not in response:
            email_confirm_token = str(uuid.uuid4())
            email_address = event['emailaddress'].strip().lower()
            user = cherrypy.request.db.getUser(email_address)
            if not user:
                self.logger.debug('Processing createAccount from IP (%s) Email (%s)' % (ip, email_address))
                now = time.time()
                _time = self.check_ip_requests(ip)
                if _time > now:
                    self.logger.debug('IP (%s) passed throttling check for Email (%s)' % (ip, email_address))
                    group = cherrypy.request.db.getGroup(group_name='Demo')
                    user = cherrypy.request.db.createUser(email_address, password=event['password'], group=group)
                    user.email_confirm_token = email_confirm_token
                    user.locked = True
                    cherrypy.request.db.updateUser(user)
                    response['created'] = True
                    demo_account_registration_link = 'https://{}/api/subscriptions/confirmEmailAddress?emailaddress={}&token={}'.format(cherrypy.request.db.config['subscription']['app_domain'].value, urllib.parse.quote(email_address), email_confirm_token)
                    demo_account_registration_href = '<a href=\"{}\" rel-\" noopener\" target=\"_blank\">Confirm Email Address</a>'.format(demo_account_registration_link)
                    try:
                        self.hubSpotRegisterContact(event, demo_account_registration_link, demo_account_registration_href)
                    except Exception as e:
                        logging.exception('Failed Sending HubSpot Account Registration : %s' % e)
                else:  # inserted
                    response['error_message'] = 'Too many requests.'
                    self.logger.warning('IP (%s) failed throttling check for Email (%s)' % (ip, email_address))
            else:  # inserted
                response['error_message'] = 'A user with this email address already exists.'
                logging.warning('Attempt to create account with existing email {0}'.format(email_address))
        if 'error_message' in response:
            logging.warning('createAccount: {0}'.format(response['error_message']))
        else:  # inserted
            logging.info('createAccount: Successful: {0}'.format(email_address))
        return json.dumps(response)

    @cherrypy.expose
    @Unauthenticated()
    def requestInformation(self):
        event = getRequestJson(cherrypy.request)
        response = {}
        recap = self.validateReCaptcha(event)
        if recap['status'] == False:
            response['error_message'] = recap['error_message'] if 'error_message' in recap else 'Unable to verify ReCaptcha'
        else:  # inserted
            if 'emailaddress' not in event or event['emailaddress'] == None or (not is_valid_email_address(event['emailaddress'])):
                response['error_message'] = 'Invalid Email Address'
            else:  # inserted
                if 'name' not in event or event['name'] == None:
                    response['error_message'] = 'Please provide a name.'
                else:  # inserted
                    if 'message' not in event or event['message'] == None:
                        response['error_message'] = 'Please provide a message.'
                    else:  # inserted
                        if 'phone' not in event or event['phone'] == None:
                            response['error_message'] = 'Please provide a phone number.'
        if 'error_message' not in response:
            body = '\n            <html>\n                <head></head>\n                <body>\n                  <h1>Kasm Workspaces - Unauthenticated Request For Information</h1>\n                  <p>From: {1} <a href=\'mailto:{0}\'>{0}</a></p>\n                  <p>\n                    Phone: {2}\n                    {3}\n                  </p>\n                </body>\n            </html>\n            '
            self.sendEmailHTML('info@kasmweb.com', 'KasmWeb Request For Information', body.format(event['emailaddress'], event['name'], event['phone'], event['message']))
        if 'error_message' in response:
            logging.warning('requestInformation: {0}: {1}'.format(response['error_message'], event))
        else:  # inserted
            logging.info('requestInformation: Successful: {0}'.format(event['emailaddress']))
        return json.dumps(response)

    @cherrypy.expose
    @Unauthenticated()
    def confirmEmailAddress(self, emailaddress, token, **params):
        user = cherrypy.request.db.getUser(emailaddress)
        location = cherrypy.request.db.config['subscription']['app_domain'].value
        response = '\n        <html>\n            <head><meta http-equiv=\'refresh\' content=\'5; url=https://{location}\' /></head>\n            <body>Email Confirmation {status}, redirecting to <a href=\'http://{location}\'>login</a></body>\n        </html>\n        '
        if user.email_confirm_token:
            if user.locked == True:
                if user.email_confirm_token == token:
                    user.locked = False
                    user.email_confirm_token = None
                    cherrypy.request.db.updateUser(user)
                    response = response.format(location=location, status='Successful')
                else:  # inserted
                    logging.warning('Attempt to confirm email with invalid token for user {} with token {}'.format(emailaddress, token))
                    response = response.format(location=location, status='Failed')
        logging.warning('Invalid attempt to confirm email for user {} with token {}'.format(emailaddress, token))
        response = response.format(location=location, status='Failed')
        return response

    @cherrypy.expose
    @Unauthenticated()
    def authorizeUserAccess(self):
        event = getRequestJson(cherrypy.request)
        response = dict()
        response['authorized'] = False
        if 'username' in event and 'token' in event:
            user = cherrypy.request.db.getUser(event['username'])
            if user:
                if cherrypy.request.db.validateSessionToken(event['token'], user.username):
                    if user.stripe_id is None:
                        response['error_message'] = 'User not subscribed to a plan.'
                        logging.warning('User (%s) requested authorization, no stripe account.' % event['username'])
                    else:  # inserted
                        cust = stripe.Customer.retrieve(user.stripe_id)
                        if len(cust.subscriptions.data) > 0:
                            response['subscription_status'] = cust.subscriptions.data[0].status
                            if cust.subscriptions.data[0].status == 'trialing' or cust.subscriptions.data[0].status == 'active':
                                response['authorized'] = True
                            else:  # inserted
                                if cust.subscriptions.data[0].status == 'past_due':
                                    response['authorized'] = True
                                    response['error_message'] = 'Your account is past due, please check your profile and update your payment method.'
                                else:  # inserted
                                    response['error_message'] = 'Your subscription has either been cancelled or is in an unpaid status'
                        else:  # inserted
                            response['error_message'] = 'Access Denied, user not subscribed to a plan.'
                            logging.warning('User (%s) requested authorization, user not subscribed to a plan.' % event['username'])
                else:  # inserted
                    response['error_message'] = 'Access Denied'
            else:  # inserted
                logging.warning('User (%s) is not a valid username' % event['username'])
                response['error_message'] = 'Access Denied'
        else:  # inserted
            logging.warning('Invalid request to update payment information')
            response['error_message'] = 'Access Denied'
        return json.dumps(response)

    @cherrypy.expose
    @Unauthenticated()
    def updatePaymentInfo(self):
        event = getRequestJson(cherrypy.request)
        response = {}
        if 'username' in event and 'token' in event and ('stripetoken' in event):
            user = cherrypy.request.db.getUser(event['username'])
            if user:
                if cherrypy.request.db.validateSessionToken(event['token'], user.username):
                    print('Stripe Token: (%s)' % event['stripetoken'])
                    if user.stripe_id is None:
                        stripe_id = self.createStripeUser(user)
                        if stripe_id == False:
                            response['error_message'] = 'Error creating Stripe customer record'
                    else:  # inserted
                        stripe_id = user.stripe_id
                    cust = stripe.Customer.retrieve(stripe_id)
                    card = cust.sources.all(object='card')
                    if len(card.data) > 0:
                        cust.sources.retrieve(card.data[0].id).delete()
                    newcard = cust.sources.create(source=event['stripetoken']['id'])
                    cust.default_source = newcard.id
                    cust.save()
                    response['default_card'] = {'brand': newcard.brand, 'last4': newcard.last4, 'exp_month': newcard.exp_month, 'exp_year': newcard.exp_year}
                else:  # inserted
                    response['error_message'] = 'Access Denied'
            else:  # inserted
                logging.warning('User (%s) is not a valid username' % event['username'])
                response['error_message'] = 'Access Denied'
        else:  # inserted
            logging.warning('Invalid request to update payment information')
            response['error_message'] = 'Access Denied'
        return json.dumps(response)

    @cherrypy.expose
    @Unauthenticated()
    def getProducts(self):
        return json.dumps(self.get_stripe_products())

    @cherrypy.expose
    @Unauthenticated()
    def getUserProfile(self):
        event = getRequestJson(cherrypy.request)
        response = {}
        if 'username' in event and 'token' in event:
            user = cherrypy.request.db.getUser(event['username'])
            if user:
                if user.stripe_id is None:
                    custid = self.createStripeUser(user)
                else:  # inserted
                    custid = user.stripe_id
                cust = stripe.Customer.retrieve(custid)
                if cherrypy.request.db.validateSessionToken(event['token'], user.username):
                    subscriptions = stripe.Plan.list()
                    response['plans'] = []
                    for s in subscriptions.data:
                        plan = {'name': s['name'], 'amount': s['amount'], 'description': s['metadata']['description'], 'id': s['id'], 'is_selected': False}
                        if len(cust.subscriptions.data) > 0 and cust.subscriptions.data[0].plan.id == s['id']:
                            plan['is_selected'] = True
                        response['plans'].append(plan)
                    if len(cust.sources.data) > 0:
                        card = {'brand': cust.sources.data[0].brand, 'last4': cust.sources.data[0].last4, 'exp_month': cust.sources.data[0].exp_month, 'exp_year': cust.sources.data[0].exp_year}
                        response['default_card'] = card
                    if len(cust.subscriptions.data) > 0:
                        response['subscription_status'] = cust.subscriptions.data[0].status
                else:  # inserted
                    response['error_message'] = 'Access Denied'
            else:  # inserted
                logging.warning('User (%s) is not a valid username' % event['username'])
                response['error_message'] = 'Access Denied'
        return json.dumps(response)

    @cherrypy.expose
    @Unauthenticated()
    def cancelUserSubscription(self):
        event = getRequestJson(cherrypy.request)
        response = {}
        if 'username' in event and 'token' in event:
            user = cherrypy.request.db.getUser(event['username'])
            if user:
                if cherrypy.request.db.validateSessionToken(event['token'], user.username):
                    if 'stripe_id' in user:
                        cust = stripe.Customer.retrieve(user.stripe_id)
                        if len(cust.subscriptions.data) > 0:
                            subscription = stripe.Subscription.retrieve(cust.subscriptions.data[0].id)
                            subscription.delete()
                            user.plan_id = None
                            cherrypy.request.db.updateUser(user)
                        else:  # inserted
                            response['error_message'] = 'You are not subscribed to a plan.'
                            logging.warning('User {} attempted to cancel plan, but they are not a assigned a plan in stripe'.format(event['username']))
                    else:  # inserted
                        response['error_message'] = 'You are not subscribed to a plan.'
                        logging.warning('User {} attempted to cancel plan, but they do not have a Stripe account.'.format(event['username']))
                else:  # inserted
                    response['error_message'] = 'Access Denied'
                    logging.warning('Invalid token for user {} to cancelUserSubscription'.format(event['username']))
            else:  # inserted
                response['error_message'] = 'Access Denied'
                logging.warning('Invalid username {} to cancelUserSubscription'.format(event['username']))
        else:  # inserted
            logging.warning('Invalid request to cancelUserSubscription')
            response['error_message'] = 'Invalid request'
        return json.dumps(response)

    @cherrypy.expose
    @Unauthenticated()
    def setUserSubscription(self):
        event = getRequestJson(cherrypy.request)
        response = {}
        if 'username' in event and 'token' in event and ('plan_id' in event):
            user = cherrypy.request.db.getUser(event['username'])
            if not user or cherrypy.request.db.validateSessionToken(event['token'], user.username):
                if user.stripe_id is None:
                    stripe_id = self.createStripeUser(user)
                    if stripe_id == False:
                        response['error_message'] = 'Error creating Stripe customer record'
                        return json.dumps(response)
                else:  # inserted
                    stripe_id = user.stripe_id
                try:
                    subs = stripe.Subscription.list(customer=stripe_id)
                    if len(subs.data) == 0:
                        stripe.Subscription.create(customer=stripe_id, items=[{'plan': event['plan_id']}])
                    else:  # inserted
                        current_sub = stripe.Subscription.retrieve(subs.data[0].id)
                        print(current_sub)
                        current_sub.plan = event['plan_id']
                        current_sub.save()
                    user.plan_id = event['plan_id']
                    cherrypy.request.db.updateUser(user)
                except stripe.error.InvalidRequestError as ex:
                    response['error_message'] = str(ex)
                    if 'This customer has no attached payment source' in response['error_message']:
                        response['error_message'] = 'Before you can select a plan, you must setup a payment.'
                except Exception as ex2:
                    response['error_message'] = 'An unexpected error occurred.'
                    print(ex2)
            else:  # inserted
                response['error_message'] = 'Access Denied'
            if 'error_message' in response:
                logging.warning('Error setting user {} plan to {}: {}'.format(event['username'], event['plan_id'], response['error_message']))
        else:  # inserted
            logging.warning('Invalid request to setUserSubscription')
            response['error_message'] = 'Invalid request'
        return json.dumps(response)

    @cherrypy.expose()
    @Unauthenticated()
    def confirm_subscription(self):
        print('confirmed')

    @cherrypy.expose()
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Unauthenticated()
    def create_cart(self):
        response = {}
        event = cherrypy.request.json
        if 'email' not in event or event['email'] == None or (not is_valid_email_address(event['email'])):
            response['error_message'] = 'Invalid Email Address'
            return response
        if 'password' not in event or event['password'] == None:
            response['error_message'] = 'Please enter a password'
            return response
        pwr = passwordComplexityCheck(event['password'], require_lower=False, require_upper=False, require_special=False, require_numbers=False)
        if not pwr['status']:
            response['error_message'] = pwr['message']
            return response
        verify_email_addresses = cherrypy.request.db.get_config_setting_bool('subscription', 'verify_email_addresses', True)
        if verify_email_addresses:
            is_verified = self.is_email_verified(event['email'].split('@')[1])
            if not is_verified:
                self.logger.warning('Account for address %s is rejected' % event['email'])
                response['error_message'] = 'Accounts are not allowed from this domain'
                return response
        else:  # inserted
            logging.debug('Spam email validation disabled')
        email_address = event['email'].strip().lower()
        user = cherrypy.request.db.getUser(email_address)
        if not user:
            user = cherrypy.request.db.createUser(username=email_address, password=event['password'], first_name=event['first_name'], last_name=event['last_name'])
            if user:
                stripe_id = self.createStripeUser(user)
                if stripe_id:
                    cart = cherrypy.request.db.createCart(plan_name=event['plan_name'], stripe_id=stripe_id, user_id=user.user_id)
                    if cart:
                        if cart.cart_id:
                            response['cart_id'] = cherrypy.request.db.serializable(cart.cart_id)
                            return response
                    response['error_message'] = 'Error creating Cart'
                    return response
                response['error_message'] = 'Error Creating Stripe User %s' % email_address
                return response
            response['error_message'] = 'Error Creating User %s' % email_address
            return response
        response['error_message'] = 'User with email address %s Already Exists' % email_address
        return response

    @cherrypy.expose()
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Unauthenticated()
    def stripe_checkout_id(self):
        response = {}
        event = cherrypy.request.json
        cart = cherrypy.request.db.getCart(event['cart_id'])
        if cart or not cart.completed:
            user = cherrypy.request.db.get_user_by_id(cart.user_id)
            plan_name = cart.plan_name
            if user:
                try:
                    session = stripe.checkout.Session.create(payment_method_types=['card'], customer=cart.stripe_id, subscription_data={'items': [{'plan': plan_name}]}, client_reference_id=cart.cart_id, billing_address_collection='required', success_url='https://' + cherrypy.request.db.config['subscription']['website_domain'].value + '/checkout_complete.html#?session_id={CHECKOUT_SESSION_ID}', cancel_url='https://' + cherrypy.request.db.config['subscription']['website_domain'].value + '/checkout.html#?cart_id=' + cherrypy.request.db.serializable(cart.cart_id))
                except stripe.error.InvalidRequestError:
                    self.logger.error('Invalid Request Sent to Stripe: %s', traceback.format_exc())
                    response['error_message'] = 'Invalid Request made to Stripe'
                    return response
                except stripe.error.StripeError:
                    self.logger.error('Invalid Request Sent to Stripe: %s', traceback.format_exc())
                    response['error_message'] = 'Stripe Encountered an Error'
                    return response
                else:  # inserted
                    plans = []
                    for item in session['display_items']:
                        product = self.getProduct(item['plan']['product'])
                        if product:
                            plans.append({'name': product['name'], 'description': product['description'], 'quantity': item['quantity'], 'amount': item['amount'], 'plan_name': item['plan']['nickname']})
                response['cart'] = {'name': user.first_name + ' ' + user.last_name, 'email': user.username, 'phone': user.phone, 'session_id': session.id, 'plans': plans}
                return response
            else:  # inserted
                msg = 'Error Finding Cart User. Try Creating another cart.'
                response['error_message'] = msg
                return response
        else:  # inserted
            msg = 'Cart for that ID is no longer Valid.'
            response['error_message'] = msg
            return response

    @cherrypy.expose()
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @Unauthenticated()
    def checkout_complete(self):
        response = {}
        event = cherrypy.request.json
        session_id = event['session_id']
        session = stripe.checkout.Session.retrieve(session_id)
        cus = stripe.Customer.retrieve(session.customer)
        response['session'] = session
        response['customer'] = cus
        return response

    @cherrypy.expose()
    @Unauthenticated()
    @cherrypy.tools.json_out()
    def checkout_complete_hook(self):
        response = {}
        endpoint_secret = cherrypy.request.db.config['subscription']['stripe_checkout_signing_secret'].value
        payload = cherrypy.request.body.read()
        event = json.loads(payload.decode('utf-8'))
        sig_header = cherrypy.request.headers['STRIPE-SIGNATURE']
        try:
            stripe.Webhook.construct_event(payload, sig_header, endpoint_secret)
            self.logger.debug('Stripe checkout_complete_hook webhook signature validated (%s)' % sig_header)
        except ValueError as e:
            self.logger.error('Stripe Payload Invalid: %s', e)
            cherrypy.response.status = 400
            return
        except stripe.error.SignatureVerificationError as e:
            self.logger.error('Stripe Signature Unverified: %s', e)
            cherrypy.response.status = 400
            return
        stripe_type = event['type']
        self.logger.debug('Received checkout_complete_hook for type (%s) : data (%s)' % (stripe_type, json.dumps(event, sort_keys=True)))
        if stripe_type == 'checkout.session.completed' and ('client_reference_id' in event['data']['object'] and event['data']['object']['client_reference_id'] is not None):
            cart = cherrypy.request.db.getCart(event['data']['object']['client_reference_id'])
            if cart and cart.stripe_id == event['data']['object']['customer']:
                stripe.Customer.retrieve(cart.stripe_id)
                user = cherrypy.request.db.get_user_by_id(cart.user_id)
                cherrypy.request.db.updateCart(cart, completed=True)
                self.logger.info('Completed checkout for cart %s and user %s', cart.cart_id, user.username)
            else:  # inserted
                cherrypy.response.status = 400
                msg = 'Customer did not match cart User in Checkout.Session.Completed webhook for event %s' % json.dumps(event, sort_keys=True)
                self.logger.error(msg)
                response['error_message'] = msg
                return response
        else:  # inserted
            if event['data']['object']['setup_intent'] is not None:
                si = event['data']['object']['setup_intent']
                setup_intent = stripe.SetupIntent.retrieve(si)
                payment_method = setup_intent['payment_method']
                customer = setup_intent['metadata']['customer_id']
                subscription = setup_intent['metadata']['subscription_id']
                stripe.PaymentMethod.attach(payment_method, customer=customer)
                stripe.Customer.modify(customer, invoice_settings={'default_payment_method': payment_method})
                stripe.Subscription.modify(subscription, default_payment_method=payment_method)
            else:  # inserted
                self.logger.error('Stripe message will not be processed : (%s)' % json.dumps(event, sort_keys=True))

    def remove_subscription_groups(self, user):
        remove_groups = user.none_system_group_ids()
        if remove_groups:
            for group_id in remove_groups:
                group = cherrypy.request.db.getGroup(group_id)
                cherrypy.request.db.removeUserGroup(user, group)
                self.logger.info('Removed from: %s', group.name)

    @cherrypy.expose()
    @cherrypy.tools.json_out()
    @Unauthenticated()
    def subscription_hooks(self):
        stripe.api_version = '2022-11-15'
        stripe.api_key = cherrypy.request.db.get_config_setting_value('subscription', 'stripe_private_key')
        endpoint_secret = cherrypy.request.db.get_config_setting_value('subscription', 'stripe_subscription_signing_secret')
        payload = cherrypy.request.body.read()
        event = json.loads(payload.decode('utf-8'))
        sig_header = cherrypy.request.headers['STRIPE-SIGNATURE']
        try:
            stripe.Webhook.construct_event(payload, sig_header, endpoint_secret)
            self.logger.debug('Stripe webhook signature validated (%s)' % sig_header)
        except ValueError as e:
            self.logger.error('Stripe Payload Invalid: %s', e)
            cherrypy.response.status = 400
            return
        except stripe.error.SignatureVerificationError as e:
            self.logger.error('Stripe Signature Unverified: %s', e)
            cherrypy.response.status = 400
            return
        stripe_type = event['type']
        customer_id = event['data']['object']['customer']
        user = cherrypy.request.db.get_user_by_stripe_id(customer_id)
        if not user:
            cust = stripe.Customer.retrieve(customer_id)
            user = cherrypy.request.db.getUser(cust['email'])
            if user:
                user.stripe_id = customer_id
            else:  # inserted
                self.logger.error('Received webhook for unknown user (%s)' % cust['email'])
        self.logger.info('Received subscription hook (%s) for stripe customer (%s) : username (%s)  data (%s)' % (stripe_type, customer_id, user.username if user else 'Unknown', json.dumps(event, sort_keys=True)))
        if user:
            user.subscription_id = event['data']['object']['id']
            user.plan_id = event['data']['object']['plan']['id']
            user.plan_end_date = datetime.datetime.fromtimestamp(event['data']['object']['current_period_end'])
            user.plan_start_date = datetime.datetime.fromtimestamp(event['data']['object']['current_period_start'])
            user_groups = user.get_group_ids()
            if stripe_type == 'customer.subscription.deleted':
                product_id = event['data']['object']['plan']['product']
                product = stripe.Product.retrieve(product_id)
                product_name = product['name']
                group_assignment = product['metadata']['group_assignment_label'].strip()
                plan_nickname = event['data']['object']['plan']['nickname']
                user.plan_id = None
                try:
                    self.hubSpotRegisterContactSubscription(user.username, user.stripe_id, user.plan_id, product_id, product_name, plan_nickname, 'False')
                except Exception as e:
                    self.logger.exception('Exception Sending Hubspot update: %s' % e)
                self.logger.info('Stripe Subscription Deleted. Removing User: %s from Subscription Groups', user.username)
                self.remove_subscription_groups(user)
                user_groups = user.get_group_ids()
            else:  # inserted
                if stripe_type == 'customer.subscription.updated' or stripe_type == 'customer.subscription.created':
                    status = event['data']['object']['status']
                    if status == 'active':
                        product_id = event['data']['object']['plan']['product']
                        product = stripe.Product.retrieve(product_id)
                        product_name = product['name']
                        plan_nickname = event['data']['object']['plan']['nickname']
                        group_assignment = product['metadata']['group_assignment_label'].strip()
                        if event['data']['object']['plan']['metadata'].get('group_assignment_label'):
                            group_assignment = event['data']['object']['plan']['metadata']['group_assignment_label'].strip()
                        try:
                            self.hubSpotRegisterContactSubscription(user.username, user.stripe_id, user.plan_id, product_id, product_name, plan_nickname, 'True')
                        except Exception as e:
                            self.logger.exception('Exception Sending Hubspot update: %s' % e); self.logger.info('Stripe Subscription Updated. Removing User: %s from Subscription Groups', user.username); self.remove_subscription_groups(user); user.get_group_ids();
                        group = cherrypy.request.db.getGroup(meta_key='group_assignment_label', meta_value=group_assignment) if not group or group.group_id not in user_groups:
                            cherrypy.request.db.addUserGroup(user, group)(self.logger.info('Stripe Subscription Updated adding User: %s to Group %s', user.username, group.name), self.logger.error('Unknown group with group_id (%s)' % group_id), stripe=400)
                        else:  # inserted
                            cherrypy.response.status = cherrypy.response.status
                        pass
                    else:  # inserted
                        self.logger.error('No processing available subscription hook with type (%s) and status (%s)' % (stripe_type, status))
                    pass
                else:  # inserted
                    self.logger.error('No processing available subscription hook with type (%s)' % stripe_type)
                    cherrypy.response.status = cherrypy.response.status
            cherrypy.request.db.updateUser(user)
        else:  # inserted
            self.logger.error('Unknown User for customer id (%s) for event type (%s)' % (customer_id, stripe_type))

    def validateReCaptcha(self, event):
        response = {'status': False}
        if 'recaptcha' not in event or event['recaptcha'] == None or event['recaptcha'] == '':
            response['error_message'] = 'Check the I\'m not a robot box'
        else:  # inserted
            params = {'secret': cherrypy.request.db.get_config_setting_value('auth', 'google_recaptcha_priv_key'), 'response': event['recaptcha']}
            res = requests.get(cherrypy.request.db.get_config_setting_value('auth', 'google_recaptcha_api_url'), params=params, verify=True)
            res = res.json()
            if 'success' in res and res['success'] == True:
                response['status'] = True
            else:  # inserted
                if 'error-codes' in res:
                    response['error_message'] = 'Error in recaptcha request: {0}'.format(res['error-codes'])
                else:  # inserted
                    response['error_message'] = 'Unknown recaptcha error'
        return response

    def createStripeUser(self, user):
        if user.stripe_id is None:
            customer = stripe.Customer.create(email=user.username, description=user.user_id, name=user.first_name + ' ' + user.last_name)
            user.stripe_id = customer.id
            cherrypy.request.db.updateUser(user)
            return customer.id
        return False

    def sendEmailHTML(self, email_recipient, subject, content):
        client = boto3.client('ses', region_name=cherrypy.request.db.get_config_setting_value('subscription', 'ses_aws_region'), aws_access_key_id=cherrypy.request.db.get_config_setting_value('subscription', 'ses_aws_access_key_id'), aws_secret_access_key=cherrypy.request.db.get_config_setting_value('subscription', 'ses_aws_secret_access_key'))
        try:
            response = client.send_email(Destination={'ToAddresses': [email_recipient]}, Message={'Body': {'Html': {'Charset': 'UTF-8', 'Data': content}, 'Text': {'Charset': 'UTF-8', 'Data': 'The content of this email is HTML, you must use an email client that supports HTML content'}}, 'Subject': {'Charset': 'UTF-8', 'Data': subject}}, Source=cherrypy.request.db.get_config_setting_value('subscription', 'email_sender'))
        except ClientError as e:
            self.logger.error('Error occurred sending email: ' + e.response['Error']['Message'])
            return False
        return True