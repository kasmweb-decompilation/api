# Source Generated with Decompyle++
# File: subscription_api.pyc (Python 3.8)

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
import logging.config as logging
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
        pass
    # WARNING: Decompyle incomplete

    
    def requestResetEmail(self):
        event = getRequestJson(cherrypy.request)
        response = { }
        recap = self.validateReCaptcha(event)
        if recap['status'] == False:
            response['error_message'] = recap['error_message'] if 'error_message' in recap else 'Unable to verify ReCaptcha'
        elif not 'emailaddress' not in event and event['emailaddress'] == None or is_valid_email_address(event['emailaddress']):
            response['error_message'] = 'Invalid Email Address'
        else:
            user = cherrypy.request.db.getUser(event['emailaddress'])
            if user is None:
                self.logger.error('Password reset email requested for non-registered address %s' % event['emailaddress'])
            else:
                pw_reset_token = str(uuid.uuid4())
                user.locked = False
                user.email_confirm_token = pw_reset_token
                user.email_pw_reset_request_date = datetime.datetime.utcnow()
                cherrypy.request.db.updateUser(user)
                body = "\n                <html>\n                    <head></head>\n                    <body>\n                      <h1>Kasm Workspaces</h1>\n                      <p>A password reset has been requested for this account. Click this \n                        <a href='https://{}/#/reset?emailaddress={}&token={}'>Password Rest Link </a> to reset your password.\n                      </p>\n                    </body>\n                </html>\n                "
                self.sendEmailHTML(event['emailaddress'], 'Kasm - Password Reset Request', body.format(cherrypy.request.db.get_config_setting_value('subscription', 'app_domain'), urllib.parse.quote(event['emailaddress']), pw_reset_token))
        return json.dumps(response)

    requestResetEmail = cherrypy.expose(Unauthenticated()(requestResetEmail))
    
    def passwordReset(self):
        event = getRequestJson(cherrypy.request)
        response = { }
        recap = self.validateReCaptcha(event)
        if recap['status'] == False:
            response['error_message'] = recap['error_message'] if 'error_message' in recap else 'Unable to verify ReCaptcha'
        elif not 'emailaddress' not in event and event['emailaddress'] == None or is_valid_email_address(event['emailaddress']):
            response['error_message'] = 'Invalid Email Address'
        elif 'reset_token' not in event or event['reset_token'] == None:
            response['error_message'] = 'Access Denied'
        elif 'password' in event:
            pwr = passwordComplexityCheck(event['password'], False, False, False, False, **('require_lower', 'require_upper', 'require_special', 'require_numbers'))
            if not pwr['status']:
                response['error_message'] = pwr['message']
        if 'error_message' not in response:
            email_address = event['emailaddress'].strip().lower()
            user = cherrypy.request.db.getUser(email_address)
            if user:
                if user.email_confirm_token and user.email_pw_reset_request_date:
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
                        else:
                            response['error_message'] = 'Password reset token is not valid'
                    else:
                        response['error_message'] = 'Email password reset token has expired'
                else:
                    response['error_message'] = 'Password reset token is not valid'
        if 'error_message' in response:
            logging.warning('passwordReset: {0}'.format(response['error_message']))
        else:
            logging.info('passwordReset: Successful: {0}'.format(event['emailaddress']))
        return json.dumps(response)

    passwordReset = cherrypy.expose(Unauthenticated()(passwordReset))
    
    def cancelNewsletter(self):
        event = getRequestJson(cherrypy.request)
        response = { }
        recap = self.validateReCaptcha(event)
        if recap['status'] == False:
            response['error_message'] = recap['error_message'] if 'error_message' in recap else 'Unable to verify ReCaptcha'
        elif not 'emailaddress' not in event and event['emailaddress'] == None or is_valid_email_address(event['emailaddress']):
            response['error_message'] = 'Invalid Email Address'
        if 'error_message' not in response:
            newsletter = cherrypy.request.db.getNewsletter(event['emailaddress'])
            if newsletter:
                newsletter.enabled = False
                cherrypy.request.db.updateNewsletter(newsletter)
            else:
                response['error_message'] = 'This email address is not currently subscribed to the newsletter.'
        if 'error_message' in response:
            logging.warning('cancelNewsletter: {0}: {1}'.format(response['error_message'], event))
        else:
            logging.info('cancelNewsletter: Successful')
        return json.dumps(response)

    cancelNewsletter = cherrypy.expose(Unauthenticated()(cancelNewsletter))
    
    def signupNewsletter(self):
        event = getRequestJson(cherrypy.request)
        response = { }
        recap = self.validateReCaptcha(event)
        if recap['status'] == False:
            response['error_message'] = recap['error_message'] if 'error_message' in recap else 'Unable to verify ReCaptcha'
        elif not 'emailaddress' not in event and event['emailaddress'] == None or is_valid_email_address(event['emailaddress']):
            response['error_message'] = 'Invalid Email Address'
        if 'error_message' not in response:
            newsletter = cherrypy.request.db.getNewsletter(event['emailaddress'])
            if not newsletter:
                cherrypy.request.db.createNewsletter(event['emailaddress'], 'general')
            elif newsletter.enabled:
                response['error_message'] = 'This email address is already registered.'
            else:
                newsletter.enabled = True
                cherrypy.request.db.updateNewsletter(newsletter)
        if 'error_message' in response:
            logging.warning('signupNewsletter: {0}: {1}'.format(response['error_message'], event))
        else:
            logging.info('signupNewsletter: Successful')
        return json.dumps(response)

    signupNewsletter = cherrypy.expose(Unauthenticated()(signupNewsletter))
    
    def hubSpotRegisterContact(self, event, demo_account_registration_link, demo_account_registration_href):
        headers = { }
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
        endpoint = 'https://forms.hubspot.com/uploads/form/v2/%s/%s?&' % (cherrypy.request.db.get_config_setting_value('subscription', 'hubspot_portal_id'), cherrypy.request.db.get_config_setting_value('subscription', 'hubspot_registration_form_id'))
        hs_context = json.dumps({
            'hutk': cherrypy.request.cookie['hubspotutk'].value if cherrypy.request.cookie.get('hubspotutk') else '',
            'ipAddress': cherrypy.request.headers['X-Forwarded-For'].split(',')[0] if 'X-Forwarded-For' in cherrypy.request.headers else cherrypy.request.remote.ip,
            'pageUrl': cherrypy.request.base + cherrypy.request.path_info,
            'pageName': 'Create Account' })
        data = urllib.parse.urlencode({
            'email': event['emailaddress'],
            'hs_context': hs_context,
            'demo_account_registration_link': demo_account_registration_link,
            'demo_account_registration_href': demo_account_registration_href })
        logging.info('Sending Hubspot Registration Request: %s' % data)
        r = requests.post(endpoint, data, headers, **('url', 'data', 'headers'))
        if not r.ok:
            self.logger.error('Error sending Hubspot request: %s' % r.content.decode('utf-8'))

    
    def hubSpotRegisterContactSubscription(self, email, stripe_customer_id, stripe_plan_id, stripe_product_id, stripe_product_name, stripe_plan_nickname, stripe_enrolled):
        headers = { }
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
        endpoint = 'https://forms.hubspot.com/uploads/form/v2/%s/%s?&' % (cherrypy.request.db.get_config_setting_value('subscription', 'hubspot_portal_id'), cherrypy.request.db.get_config_setting_value('subscription', 'hubspot_subscription_form_id'))
        data = urllib.parse.urlencode({
            'email': email,
            'stripe_customer_id': stripe_customer_id,
            'stripe_plan_id': stripe_plan_id,
            'stripe_product_id': stripe_product_id,
            'stripe_product_name': stripe_product_name,
            'stripe_plan_nickname': stripe_plan_nickname,
            'stripe_enrolled': stripe_enrolled })
        logging.info('Sending Hubspot Subscription Update Request: %s' % data)
        r = requests.post(endpoint, data, headers, **('url', 'data', 'headers'))
        if not r.ok:
            self.logger.error('Error sending Hubspot request: %s' % r.content.decode('utf-8'))

    
    def is_email_verified(self, address):
        self.logger.info('Verifying Email : %s' % address)
        url = 'https://mailcheck.p.rapidapi.com/'
        querystring = {
            'disable_test_connection': 'false',
            'domain': address }
        headers = {
            'x-rapidapi-host': 'mailcheck.p.rapidapi.com',
            'x-rapidapi-key': 'cfe41ef802msh127a4f17d978e14p168b82jsnc84bd3fbe49c' }
        response = requests.request('GET', url, headers, querystring, **('headers', 'params'))
        self.logger.info('Check-Mail API response (%s)' % response.text)
        data = json.loads(response.text)
        do_block = data['block']
        if do_block:
            self.logger.warning('Block (%s) ? : (%s)' % (address, do_block))
        else:
            self.logger.info('Block (%s) ? : (%s)' % (address, do_block))
        return not data['block']

    
    def check_ip_requests(ip):
        return time.time()

    check_ip_requests = staticmethod(ttl_cache(500, 7200, **('maxsize', 'ttl'))(check_ip_requests))
    
    def createAccount(self):
        event = getRequestJson(cherrypy.request)
        response = { }
        ip = cherrypy.request.headers['X-Forwarded-For'].split(',')[0] if 'X-Forwarded-For' in cherrypy.request.headers else cherrypy.request.remote.ip
        invite_code = cherrypy.request.db.config['subscription'].get('invite_code')
        recap = self.validateReCaptcha(event)
        if recap['status'] == False:
            response['error_message'] = recap['error_message'] if 'error_message' in recap else 'Unable to verify ReCaptcha'
        elif invite_code and invite_code.value.lower() != 'none':
            if not 'invite' in event and event['invite'] != None or invite_code.value == event['invite']:
                response['error_message'] = 'Kasm is currently by invite only. Please check back soon or sign up for a news letter!'
            elif not 'emailaddress' not in event and event['emailaddress'] == None or is_valid_email_address(event['emailaddress']):
                response['error_message'] = 'Invalid Email Address'
        if 'password' not in event or event['password'] == None:
            response['error_message'] = 'Please enter a password'
        else:
            pwr = passwordComplexityCheck(event['password'], False, False, False, False, **('require_lower', 'require_upper', 'require_special', 'require_numbers'))
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
            else:
                self.logger.debug('Email (%s) passed Email Domain Blacklist check' % event['emailaddress'])
        if blacklist_ok:
            verify_email_addresses = cherrypy.request.db.get_config_setting_bool('subscription', 'verify_email_addresses', True)
            if verify_email_addresses:
                is_verified = self.is_email_verified(event['emailaddress'].split('@')[1])
                if not is_verified:
                    self.logger.warning('Account for address %s is rejected' % event['emailaddress'])
                    response['error_message'] = 'Accounts are not allowed from this domain'
                else:
                    logging.debug('Spam email validation disabled')
    # WARNING: Decompyle incomplete

    createAccount = cherrypy.expose(Unauthenticated()(createAccount))
    
    def requestInformation(self):
        event = getRequestJson(cherrypy.request)
        response = { }
        recap = self.validateReCaptcha(event)
        if recap['status'] == False:
            response['error_message'] = recap['error_message'] if 'error_message' in recap else 'Unable to verify ReCaptcha'
        elif not 'emailaddress' not in event and event['emailaddress'] == None or is_valid_email_address(event['emailaddress']):
            response['error_message'] = 'Invalid Email Address'
        elif 'name' not in event or event['name'] == None:
            response['error_message'] = 'Please provide a name.'
        elif 'message' not in event or event['message'] == None:
            response['error_message'] = 'Please provide a message.'
        elif 'phone' not in event or event['phone'] == None:
            response['error_message'] = 'Please provide a phone number.'
        if 'error_message' not in response:
            body = "\n            <html>\n                <head></head>\n                <body>\n                  <h1>Kasm Workspaces - Unauthenticated Request For Information</h1>\n                  <p>From: {1} <a href='mailto:{0}'>{0}</a></p>\n                  <p>\n                    Phone: {2}\n                    {3}\n                  </p>\n                </body>\n            </html>\n            "
            self.sendEmailHTML('info@kasmweb.com', 'KasmWeb Request For Information', body.format(event['emailaddress'], event['name'], event['phone'], event['message']))
        if 'error_message' in response:
            logging.warning('requestInformation: {0}: {1}'.format(response['error_message'], event))
        else:
            logging.info('requestInformation: Successful: {0}'.format(event['emailaddress']))
        return json.dumps(response)

    requestInformation = cherrypy.expose(Unauthenticated()(requestInformation))
    
    def confirmEmailAddress(self, emailaddress, token, **params):
        user = cherrypy.request.db.getUser(emailaddress)
        location = cherrypy.request.db.config['subscription']['app_domain'].value
        response = "\n        <html>\n            <head><meta http-equiv='refresh' content='5; url=https://{location}' /></head>\n            <body>Email Confirmation {status}, redirecting to <a href='http://{location}'>login</a></body>\n        </html>\n        "
        if user.email_confirm_token and user.locked == True:
            if user.email_confirm_token == token:
                user.locked = False
                user.email_confirm_token = None
                cherrypy.request.db.updateUser(user)
                response = response.format(location, 'Successful', **('location', 'status'))
            else:
                logging.warning('Attempt to confirm email with invalid token for user {} with token {}'.format(emailaddress, token))
                response = response.format(location, 'Failed', **('location', 'status'))
        else:
            logging.warning('Invalid attempt to confirm email for user {} with token {}'.format(emailaddress, token))
            response = response.format(location, 'Failed', **('location', 'status'))
        return response

    confirmEmailAddress = cherrypy.expose(Unauthenticated()(confirmEmailAddress))
    
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
                    else:
                        cust = stripe.Customer.retrieve(user.stripe_id)
                        if len(cust.subscriptions.data) > 0:
                            response['subscription_status'] = cust.subscriptions.data[0].status
                            if cust.subscriptions.data[0].status == 'trialing' or cust.subscriptions.data[0].status == 'active':
                                response['authorized'] = True
                            elif cust.subscriptions.data[0].status == 'past_due':
                                response['authorized'] = True
                                response['error_message'] = 'Your account is past due, please check your profile and update your payment method.'
                            else:
                                response['error_message'] = 'Your subscription has either been cancelled or is in an unpaid status'
                        else:
                            response['error_message'] = 'Access Denied, user not subscribed to a plan.'
                            logging.warning('User (%s) requested authorization, user not subscribed to a plan.' % event['username'])
                else:
                    response['error_message'] = 'Access Denied'
            else:
                logging.warning('User (%s) is not a valid username' % event['username'])
                response['error_message'] = 'Access Denied'
        else:
            logging.warning('Invalid request to update payment information')
            response['error_message'] = 'Access Denied'
        return json.dumps(response)

    authorizeUserAccess = cherrypy.expose(Unauthenticated()(authorizeUserAccess))
    
    def updatePaymentInfo(self):
        event = getRequestJson(cherrypy.request)
        response = { }
        if 'username' in event and 'token' in event and 'stripetoken' in event:
            user = cherrypy.request.db.getUser(event['username'])
            if user:
                if cherrypy.request.db.validateSessionToken(event['token'], user.username):
                    print('Stripe Token: (%s)' % event['stripetoken'])
                    if user.stripe_id is None:
                        stripe_id = self.createStripeUser(user)
                        if stripe_id == False:
                            response['error_message'] = 'Error creating Stripe customer record'
                        else:
                            stripe_id = user.stripe_id
                    cust = stripe.Customer.retrieve(stripe_id)
                    card = cust.sources.all('card', **('object',))
                    if len(card.data) > 0:
                        cust.sources.retrieve(card.data[0].id).delete()
                    newcard = cust.sources.create(event['stripetoken']['id'], **('source',))
                    cust.default_source = newcard.id
                    cust.save()
                    response['default_card'] = {
                        'brand': newcard.brand,
                        'last4': newcard.last4,
                        'exp_month': newcard.exp_month,
                        'exp_year': newcard.exp_year }
                else:
                    response['error_message'] = 'Access Denied'
            else:
                logging.warning('User (%s) is not a valid username' % event['username'])
                response['error_message'] = 'Access Denied'
        else:
            logging.warning('Invalid request to update payment information')
            response['error_message'] = 'Access Denied'
        return json.dumps(response)

    updatePaymentInfo = cherrypy.expose(Unauthenticated()(updatePaymentInfo))
    
    def getProducts(self):
        return json.dumps(self.get_stripe_products())

    getProducts = cherrypy.expose(Unauthenticated()(getProducts))
    
    def getUserProfile(self):
        event = getRequestJson(cherrypy.request)
        response = { }
        if 'username' in event and 'token' in event:
            user = cherrypy.request.db.getUser(event['username'])
            if user:
                if user.stripe_id is None:
                    custid = self.createStripeUser(user)
                else:
                    custid = user.stripe_id
                cust = stripe.Customer.retrieve(custid)
                if cherrypy.request.db.validateSessionToken(event['token'], user.username):
                    subscriptions = stripe.Plan.list()
                    response['plans'] = []
                    for s in subscriptions.data:
                        plan = {
                            'name': s['name'],
                            'amount': s['amount'],
                            'description': s['metadata']['description'],
                            'id': s['id'],
                            'is_selected': False }
                        if len(cust.subscriptions.data) > 0 and cust.subscriptions.data[0].plan.id == s['id']:
                            plan['is_selected'] = True
                        response['plans'].append(plan)
                    if len(cust.sources.data) > 0:
                        card = {
                            'brand': cust.sources.data[0].brand,
                            'last4': cust.sources.data[0].last4,
                            'exp_month': cust.sources.data[0].exp_month,
                            'exp_year': cust.sources.data[0].exp_year }
                        response['default_card'] = card
                    if len(cust.subscriptions.data) > 0:
                        response['subscription_status'] = cust.subscriptions.data[0].status
                    else:
                        response['error_message'] = 'Access Denied'
                else:
                    logging.warning('User (%s) is not a valid username' % event['username'])
                    response['error_message'] = 'Access Denied'
        return json.dumps(response)

    getUserProfile = cherrypy.expose(Unauthenticated()(getUserProfile))
    
    def cancelUserSubscription(self):
        event = getRequestJson(cherrypy.request)
        response = { }
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
                        else:
                            response['error_message'] = 'You are not subscribed to a plan.'
                            logging.warning('User {} attempted to cancel plan, but they are not a assigned a plan in stripe'.format(event['username']))
                    else:
                        response['error_message'] = 'You are not subscribed to a plan.'
                        logging.warning('User {} attempted to cancel plan, but they do not have a Stripe account.'.format(event['username']))
                else:
                    response['error_message'] = 'Access Denied'
                    logging.warning('Invalid token for user {} to cancelUserSubscription'.format(event['username']))
            else:
                response['error_message'] = 'Access Denied'
                logging.warning('Invalid username {} to cancelUserSubscription'.format(event['username']))
        else:
            logging.warning('Invalid request to cancelUserSubscription')
            response['error_message'] = 'Invalid request'
        return json.dumps(response)

    cancelUserSubscription = cherrypy.expose(Unauthenticated()(cancelUserSubscription))
    
    def setUserSubscription(self):
        event = getRequestJson(cherrypy.request)
        response = { }
    # WARNING: Decompyle incomplete

    setUserSubscription = cherrypy.expose(Unauthenticated()(setUserSubscription))
    
    def confirm_subscription(self):
        print('confirmed')

    confirm_subscription = cherrypy.expose()(Unauthenticated()(confirm_subscription))
    
    def create_cart(self):
        response = { }
        event = cherrypy.request.json
        if not 'email' not in event and event['email'] == None or is_valid_email_address(event['email']):
            response['error_message'] = 'Invalid Email Address'
            return response
        if None not in event or event['password'] == None:
            response['error_message'] = 'Please enter a password'
            return response
        pwr = None(event['password'], False, False, False, False, **('require_lower', 'require_upper', 'require_special', 'require_numbers'))
        if not pwr['status']:
            response['error_message'] = pwr['message']
            return response
        verify_email_addresses = None.request.db.get_config_setting_bool('subscription', 'verify_email_addresses', True)
        if verify_email_addresses:
            is_verified = self.is_email_verified(event['email'].split('@')[1])
            if not is_verified:
                self.logger.warning('Account for address %s is rejected' % event['email'])
                response['error_message'] = 'Accounts are not allowed from this domain'
                return response
        logging.debug('Spam email validation disabled')
        email_address = event['email'].strip().lower()
        user = cherrypy.request.db.getUser(email_address)
        if not user:
            user = cherrypy.request.db.createUser(email_address, event['password'], event['first_name'], event['last_name'], **('username', 'password', 'first_name', 'last_name'))
            if user:
                stripe_id = self.createStripeUser(user)
                if stripe_id:
                    cart = cherrypy.request.db.createCart(event['plan_name'], stripe_id, user.user_id, **('plan_name', 'stripe_id', 'user_id'))
                    if cart and cart.cart_id:
                        response['cart_id'] = cherrypy.request.db.serializable(cart.cart_id)
                        return response
                    response['error_message'] = None
                    return response
                response['error_message'] = 'Error Creating Stripe User %s' % email_address
                return response
            response['error_message'] = 'Error Creating User %s' % email_address
            return response
        response['error_message'] = 'User with email address %s Already Exists' % email_address
        return response

    create_cart = cherrypy.expose()(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Unauthenticated()(create_cart))))
    
    def stripe_checkout_id(self):
        response = { }
        event = cherrypy.request.json
        cart = cherrypy.request.db.getCart(event['cart_id'])
        if not cart or cart.completed:
            user = cherrypy.request.db.get_user_by_id(cart.user_id)
            plan_name = cart.plan_name
            if user:
                
                try:
                    session = stripe.checkout.Session.create([
                        'card'], cart.stripe_id, {
                        'items': [
                            {
                                'plan': plan_name }] }, cart.cart_id, 'required', 'https://' + cherrypy.request.db.config['subscription']['website_domain'].value + '/checkout_complete.html#?session_id={CHECKOUT_SESSION_ID}', 'https://' + cherrypy.request.db.config['subscription']['website_domain'].value + '/checkout.html#?cart_id=' + cherrypy.request.db.serializable(cart.cart_id), **('payment_method_types', 'customer', 'subscription_data', 'client_reference_id', 'billing_address_collection', 'success_url', 'cancel_url'))
                finally:
                    pass
                except stripe.error.InvalidRequestError:
                    self.logger.error('Invalid Request Sent to Stripe: %s', traceback.format_exc())
                    response['error_message'] = 'Invalid Request made to Stripe'
                    return None
                    except stripe.error.StripeError:
                        response
                        self.logger.error('Invalid Request Sent to Stripe: %s', traceback.format_exc())
                        response['error_message'] = 'Stripe Encountered an Error'
                        return None
                    else:
                        plans = []
                        for item in session['display_items']:
                            product = self.getProduct(item['plan']['product'])
                            if product:
                                plans.append({
                                    'name': product['name'],
                                    'description': product['description'],
                                    'quantity': item['quantity'],
                                    'amount': item['amount'],
                                    'plan_name': item['plan']['nickname'] })
                                continue
                                response['cart'] = {
                                    'name': user.first_name + ' ' + user.last_name,
                                    'email': user.username,
                                    'phone': user.phone,
                                    'session_id': session.id,
                                    'plans': plans }
                                return response
                            msg = None
                            response['error_message'] = msg
                            return response
                        msg = 'Cart for that ID is no longer Valid.'
                        response['error_message'] = msg
                        return response
                    return None


    stripe_checkout_id = cherrypy.expose()(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Unauthenticated()(stripe_checkout_id))))
    
    def checkout_complete(self):
        response = { }
        event = cherrypy.request.json
        session_id = event['session_id']
        session = stripe.checkout.Session.retrieve(session_id)
        cus = stripe.Customer.retrieve(session.customer)
        response['session'] = session
        response['customer'] = cus
        return response

    checkout_complete = cherrypy.expose()(cherrypy.tools.json_in()(cherrypy.tools.json_out()(Unauthenticated()(checkout_complete))))
    
    def checkout_complete_hook(self):
        response = { }
        endpoint_secret = cherrypy.request.db.config['subscription']['stripe_checkout_signing_secret'].value
        payload = cherrypy.request.body.read()
        event = json.loads(payload.decode('utf-8'))
        sig_header = cherrypy.request.headers['STRIPE-SIGNATURE']
    # WARNING: Decompyle incomplete

    checkout_complete_hook = cherrypy.expose()(Unauthenticated()(cherrypy.tools.json_out()(checkout_complete_hook)))
    
    def remove_subscription_groups(self, user):
        remove_groups = user.none_system_group_ids()
        if remove_groups:
            for group_id in remove_groups:
                group = cherrypy.request.db.getGroup(group_id)
                cherrypy.request.db.removeUserGroup(user, group)
                self.logger.info('Removed from: %s', group.name)

    
    def subscription_hooks(self):
        stripe.api_version = '2022-11-15'
        stripe.api_key = cherrypy.request.db.get_config_setting_value('subscription', 'stripe_private_key')
        endpoint_secret = cherrypy.request.db.get_config_setting_value('subscription', 'stripe_subscription_signing_secret')
        payload = cherrypy.request.body.read()
        event = json.loads(payload.decode('utf-8'))
        sig_header = cherrypy.request.headers['STRIPE-SIGNATURE']
    # WARNING: Decompyle incomplete

    subscription_hooks = cherrypy.expose()(cherrypy.tools.json_out()(Unauthenticated()(subscription_hooks)))
    
    def validateReCaptcha(self, event):
        response = {
            'status': False }
        if 'recaptcha' not in event and event['recaptcha'] == None or event['recaptcha'] == '':
            response['error_message'] = "Check the I'm not a robot box"
        else:
            params = {
                'secret': cherrypy.request.db.get_config_setting_value('auth', 'google_recaptcha_priv_key'),
                'response': event['recaptcha'] }
            res = requests.get(cherrypy.request.db.get_config_setting_value('auth', 'google_recaptcha_api_url'), params, True, **('params', 'verify'))
            res = res.json()
            if 'success' in res and res['success'] == True:
                response['status'] = True
            elif 'error-codes' in res:
                response['error_message'] = 'Error in recaptcha request: {0}'.format(res['error-codes'])
            else:
                response['error_message'] = 'Unknown recaptcha error'
        return response

    
    def createStripeUser(self, user):
        if user.stripe_id is None:
            customer = stripe.Customer.create(user.username, user.user_id, user.first_name + ' ' + user.last_name, **('email', 'description', 'name'))
            user.stripe_id = customer.id
            cherrypy.request.db.updateUser(user)
            return customer.id
        return None

    
    def sendEmailHTML(self, email_recipient, subject, content):
        client = boto3.client('ses', cherrypy.request.db.get_config_setting_value('subscription', 'ses_aws_region'), cherrypy.request.db.get_config_setting_value('subscription', 'ses_aws_access_key_id'), cherrypy.request.db.get_config_setting_value('subscription', 'ses_aws_secret_access_key'), **('region_name', 'aws_access_key_id', 'aws_secret_access_key'))
    # WARNING: Decompyle incomplete


