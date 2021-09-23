# -*- coding: utf-8 -*-
# Part of Odoo. See LICENSE file for full copyright and licensing details.

from odoo import fields, models

import logging
_logger = logging.getLogger(__name__)

class AuthSamlProvider(models.Model):
    """Class defining the configuration values of an Saml2 provider"""

    _name = 'auth.saml.provider'
    _description = 'Saml2 provider'
    _order = 'sequence, name'

    name = fields.Char(string='SAML Provider name', required=False)  # Name of the Saml2 entity, Google, etc
    s_version = fields.Char()
    s_provider_name = fields.Char()
    s_destination_url = fields.Char()
    #Ssaml_endpoint_url = fields.Char()
    s_slo_url = fields.Char()
    s_protocol_binding = fields.Char()
    s_acs_url = fields.Char()
    s_issuer_url = fields.Char()
    s_policy_format = fields.Char()
    s_authncontextclassref = fields.Char()
    
    client_id = fields.Char(string='Client ID')  # Our identifier
    auth_endpoint = fields.Char(string='Authentication URL', required=False)  # Saml provider URL to authenticate users
    scope = fields.Char()  # Saml user data desired to access
    validation_endpoint = fields.Char(string='Validation URL', required=False)  # Saml provider URL to validate tokens
    saml_validation_endpoint = fields.Char(string='SAML Validation URL', required=False)  # Saml provider URL to validate tokens
    data_endpoint = fields.Char(string='Data URL')
    saml_data_endpoint = fields.Char(string='SAML Data URL')
    enabled = fields.Boolean(string='Allowed')
    css_class = fields.Char(string='CSS class', default='fa fa-fw fa-sign-in text-primary')
    body = fields.Char(help='Link text in Login Dialog', translate=True,required=False)
    sequence = fields.Integer(default=10)
    image = fields.Binary()
    
    def get_provider_id(self,saml_issuer):
        saml_issuer_id = self.search([
            ('s_issuer_url','=',saml_issuer)
        ], limit=1)
        
        return saml_issuer_id