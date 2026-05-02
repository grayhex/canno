import importlib
import os
import unittest


class SmokeImportTest(unittest.TestCase):
    def test_app_import_bootstrap(self):
        os.environ.setdefault('CANNO_ADMIN_PASSWORD', 'test-admin-password')
        module = importlib.import_module('app')
        self.assertTrue(hasattr(module, 'H'))
        self.assertTrue(callable(module.init_db))


if __name__ == '__main__':
    unittest.main()
