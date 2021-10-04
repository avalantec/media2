# -*- coding: utf-8 -*-
# Part of Odoo. See LICENSE file for full copyright and licensing details.

import json

import requests

from odoo import api, fields, models
from odoo.exceptions import AccessDenied, UserError
from odoo.addons.auth_signup.models.res_users import SignupError

from odoo.addons import base
base.models.res_users.USER_PRIVATE_FIELDS.append('saml_access_token')


from lxml import etree

import logging
_logger = logging.getLogger(__name__)

class ResUsers(models.Model):
    _inherit = 'res.users'
    
    _logger.info("Loading MODELS RES USERS")

    saml_provider_id = fields.Many2one('auth.saml.provider', string='SAML Provider')
    saml_uid = fields.Char(string='SAML User ID', help="SAML Provider user_id", copy=False)
    saml_access_token = fields.Char(string='SAML Access Token', readonly=True, copy=False)
    saml_authninstant = fields.Char(string="Instant Authenticated")

    
    _sql_constraints = [
        ('uniq_users_saml_provider_saml_uid', 'unique(saml_provider_id, saml_uid)', 'SAML UID must be unique per provider'),
    ]
    

    @api.model
    def _auth_saml_rpc(self, saml_endpoint, saml_access_token):
        _logger.info("1632451601 =====DEB _AUTH_SAML_RPC")
        STOP33_NO_SE_USA

        '''
        output = { 'user_id': 928281, 'scope': 'userinfo',
                   #'expires_in': 3599, 
                  'expires_in': 10, 
                   'audience': 'cd35f598-02d2-4e4a-a18f-e5a12fbf41a3',
                   'support': False,
                   'email': 'test1@l.localhost',
                   'name': 'test1'}
        
        _logger.info("1626899001 FIN _auth_oauth_rpc output: %s", output)
        
        #return requests.get(saml_endpoint, params={'access_token': access_token}).json()
        return output
        '''

    @api.model
    def _auth_saml_validate(self, saml_params):
        _logger.info("1632451602 ====DEB _auth_saml_validate")
        _logger.info("52=====res_users auth_saml_validate saml_params: %s", saml_params)
        saml_provider_int = saml_params['state']['p']
        
        saml_provider = self.env['auth.saml.provider'].browse(saml_provider_int)
        _logger.info("56=====res_users auth_saml_validate saml_provider: %s", saml_provider)
        saml_name_id_format = saml_params['saml_name_id_format']
        user_id = ""
        email = ""
        if saml_name_id_format == "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress":
            user_id = saml_params['saml_name_id']
            email = saml_params['saml_name_id']
        
        if saml_name_id_format == None:
            _logger.info("65======saml_name_id_format NONE, USING EMAIL AS DEFAULT")
            user_id = saml_params['saml_name_id']
            email = saml_params['saml_name_id']
        
        
        audience = self.env['ir.config_parameter'].get_param('database.uuid')

        saml_validation = {
            'user_id': user_id,
            'scope': saml_params['scope'],
            'expires_in': saml_params['expires_in'],
            'audience': audience,
            'support': False,
            'email': email,
        }
        _logger.info("78===== res_users saml_validation params: %s", saml_validation)

        if saml_validation.get("error"):
            raise Exception(saml_validation['error'])
            
        return saml_validation

    @api.model
    def _generate_saml_signup_values(self, saml_provider, saml_validation, saml_params):
        _logger.info("1632451603 ====DEB _generate_saml_signup_values")
        
        saml_uid = saml_validation['user_id']
        email = saml_validation.get('email', 'provider_%s_user_%s' % (saml_provider, saml_uid))
        name = saml_validation.get('name', email)
        return {
            'name': name,
            'login': email,
            'email': email,
            'saml_provider_id': saml_provider,
            'saml_uid': saml_uid,
            'saml_access_token': saml_params['access_token'],
            'active': True,
        }

    @api.model
    def _auth_saml_signin(self, saml_provider, saml_validation, saml_params):
        _logger.info("1632451604 ====DEB _auth_saml_signin")
        _logger.info("1632451604a ====DEB saml_params: %s", saml_params)
        
        saml_uid = saml_validation['user_id']
        
        saml_user = ""
        _logger.info("1632451604b ====DEB " )
        if saml_params['saml_name_id_format'] == "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress":
            _logger.info("1632451604ba ====DEB " )
            saml_user = self.search(
                [("login", "=", saml_uid), ('saml_provider_id', '=', saml_provider)])
            _logger.info("1632451604bb ====DEB " )
            
        else:
            _logger.info("1632451604bc ====DEB " )
            saml_user = self.search(
                [("saml_uid", "=", saml_uid), ('saml_provider_id', '=', saml_provider)])

        #_logger.info("1632451604c auth_saml_signing saml_user: %s", saml_user[''])
        
        #nuevo procedimiento, en caso que sí esté el LOGIN MAIL y no tenga asociado nada
        '''
        if not saml_user:
            saml_user = self.search(
                [("login", "=", saml_uid), ('saml_provider_id', '=', False)])
            
            try:
                assert len(saml_user) == 1
                saml_user.write({'saml_access_token': saml_params['access_token']})
                saml_user.write( {'saml_provider_id': saml_params['state']['p']} )
                _logger.info("128 auth_saml_signing NUEVO TRY saml_user: %s", saml_user)
                return saml_user.login
            except AccessDenied as access_denied_exception:
                 raise access_denied_exception
                
            #raise AccessDenied()
        _logger.info("126 auth_saml_signing saml_user: %s", saml_user)
        STOP121
        '''
        _logger.info("1632451604d ======DEB")
        
        try:
            
            if not saml_user:
                raise AccessDenied()
            assert len(saml_user) == 1
            saml_user.write({
                'saml_access_token': saml_params['access_token'],
                'saml_authninstant': saml_params['saml_authn_instant'],
            })
            _logger.info("1632451604e ======DEB")
            return saml_user.login
        except AccessDenied as access_denied_exception:
            if self.env.context.get('no_user_creation'):
                return None
            _logger.info("129=== auth_saml_signin saml_params: %s", saml_params)
            
            #saml_state = json.loads(saml_params['state'])
            saml_state = saml_params['state']
            saml_token = saml_state.get('t')
            
            saml_values = self._generate_saml_signup_values(saml_provider, saml_validation, saml_params)
            try:
                _, login, _ = self.signup(saml_values, saml_token)
                return login
            except (SignupError, UserError):
                raise access_denied_exception

    @api.model
    def auth_saml(self, saml_provider, saml_params):
        _logger.info("1632451605 ====DEB auth_saml")
        _logger.info("132==== res_users auth_saml saml_provider: %s saml_params: %s", saml_provider, saml_params)
        saml_validation = self._auth_saml_validate(saml_params)

        if not saml_validation.get('user_id'):
            if saml_validation.get('id'):
                saml_validation['user_id'] = saml_validation['id']
            else:
                raise AccessDenied()

        _logger.info("148==== auth_saml auth_saml_signin")
        login = self._auth_saml_signin(saml_provider, saml_validation, saml_params)
        _logger.info("150==== auth_saml auth_saml_signin: %s", login)
        if not login:
            raise AccessDenied()

        saml_access_token = saml_params['access_token']
        output = (self.env.cr.dbname, login, saml_access_token)
        _logger.info("154==== output: %s", output )
        return output

    def _check_credentials(self, password, env):
        _logger.info("1632451606 ====DEB _check_credentials")
        _logger.info("1632451606a ===== res.users check_credentials self: %s password: %s env: %s", self, password, env)
        
        #PRUEBA SOLAMENTE PARA HACER EL REDIRECT
        
        
        
        
        try:
            return super(ResUsers, self)._check_credentials(password, env)
        except AccessDenied:
            passwd_allowed = env['interactive'] or not self.env.user._rpc_api_keys_only()
            if passwd_allowed and self.env.user.active:
                res = self.sudo().search([('id', '=', self.env.uid), ('saml_access_token', '=', password)])
                if res:
                    _logger.info("158====== res users login res: %s", res)
                    return #Login successful for db
            raise

    def _get_session_token_fields(self):
        _logger.info("1632451607 ====DEB _get_session_token_fields")
        
        saml_providers = self.env['auth.saml.provider'].sudo().search([])
        _logger.info("1632451607a DEB=====SAML_PROVIDERS: %s", saml_providers)

        
        output = super(ResUsers, self)._get_session_token_fields() | {'saml_access_token'}
        _logger.info("1632451607b======Pendiente REVISAR PORQUE SE BLOQUEA LA SESION")
        _logger.info("1632451607b======Pendiente SI NO SE TIENE UN SAML PROVIDER CONFIGURADO")
        #output = super(ResUsers, self)._get_session_token_fields()# | {'saml_access_token'}
        _logger.info("1632451607c====DEB output: %s", output)
        #return output
        return super(ResUsers, self)._get_session_token_fields() | {'saml_access_token'}
    

