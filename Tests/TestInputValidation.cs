using System;
using NUnit.Framework;
using SafeVault.Helpers;

namespace SafeVault.Tests
{
    public class TestInputValidation
    {
        [Test]
        public void TestForSQLInjection_Username_ShouldFail()
        {
            string input = "'; DROP TABLE Users; --";
            bool isValid = ValidationHelper.IsValidInput(input, InputType.Username);
            Assert.That(isValid, Is.False);
        }

        [Test]
        public void TestForXSS_Username_ShouldFail()
        {
            string input = "<script>alert('xss')</script>";
            bool isValid = ValidationHelper.IsValidInput(input, InputType.Username);
            Assert.That(isValid, Is.False);
        }

        [Test]
        public void TestForValidUsername_ShouldPass()
        {
            string input = "andrei_dev";
            bool isValid = ValidationHelper.IsValidInput(input, InputType.Username);
            Assert.That(isValid, Is.True);
        }

        [Test]
        public void TestForValidEmail_ShouldPass()
        {
            string input = "andrei@example.com";
            bool isValid = ValidationHelper.IsValidInput(input, InputType.Email);
            Assert.That(isValid, Is.True);
        }

        [Test]
        public void TestForInvalidEmail_ShouldFail()
        {
            string input = "andrei@@example..com";
            bool isValid = ValidationHelper.IsValidInput(input, InputType.Email);
            Assert.That(isValid, Is.False);
        }
    }
}