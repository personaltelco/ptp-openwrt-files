# Unit tests for generate module.


import generate
import unittest


class TestGenerator(unittest.TestCase):
    """Tests for the Generator class."""

    def testConstructor(self):
        """Test for the Generator constructor."""
        self.assertRaises(ValueError, generate.Generator)

        generator = generate.Generator(host='hostname')
        self.assertTrue(generator)
        self.assertEqual(generator.host, 'hostname')

        generator = generate.Generator(node='nodename')
        self.assertTrue(generator)
        self.assertEqual(generator.node, 'nodename')

        self.assertRaises(
            ValueError, generate.Generator, host='host', node='node')


class TestModuleFunctions(unittest.TestCase):
    """Tests for module-level functions."""

    def testMainNoArgs(self):
        """Test for the main() function without arguments."""
        self.assertEqual(generate.main(['build']), -1)

    def testMain(self):
        """Test for the main() function."""
        self.assertEqual(generate.main(['build', '-h', 'wave']), 0)
        self.assertEqual(generate.main(['build', '--host', 'wave']), 0)
        self.assertEqual(generate.main(['build', '-n', 'Keegan']), 0)
        self.assertEqual(generate.main(['build', '--node', 'Keegan']), 0)
