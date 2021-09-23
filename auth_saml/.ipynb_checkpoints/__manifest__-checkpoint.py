# -*- coding: utf-8 -*-
{
    'name': "auth_saml",

    'summary': """
        Short (1 phrase/line) summary of the module's purpose, used as
        subtitle on modules listing or apps.openerp.com""",

    'description': """
        Long description of module's purpose
    """,

    'author': "Avalantec",
    'website': "http://www.yourcompany.com",

    # Categories can be used to filter modules in modules listing
    # Check https://github.com/odoo/odoo/blob/14.0/odoo/addons/base/data/ir_module_category_data.xml
    # for the full list
    'category': 'Uncategorized',
    'version': '0.1',

    # any module necessary for this one to work correctly
    'depends': ['base', 'web', 'base_setup', 'auth_signup'],

    # always loaded
    'data': [
        'security/ir.model.access.csv',
        
        'data/auth_saml_data.xml',
        
        'views/views.xml',
        'views/templates.xml',
        'views/auth_saml_templates.xml',
        'views/auth_saml_views.xml',
        'views/res_users_views.xml',
    ],
    # only loaded in demonstration mode
    'demo': [
        'demo/demo.xml',
    ],
}
