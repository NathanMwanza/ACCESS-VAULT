import { useState } from 'react';
import { Link } from 'react-router-dom';
import AuthLayout from '../components/AuthLayout.jsx';
import TextField from '../components/TextField.jsx';
import PasswordField from '../components/PasswordField.jsx';
import PasswordStrengthMeter from '../components/PasswordStrengthMeter.jsx';
import Button from '../components/Button.jsx';
import Alert from '../components/Alert.jsx';
import { useAuth } from '../context/AuthContext.jsx';
import { validateRegisterForm, PASSWORD_MIN_LENGTH } from '../utils/validation.js';
import { ERROR_CODES } from '../services/contract.js';

export default function RegisterPage() {
  const { register } = useAuth();

  const [values, setValues] = useState({ displayName: '', email: '', password: '', confirmation: '' });
  const [fieldErrors, setFieldErrors] = useState({});
  const [formError, setFormError] = useState(null);
  const [submitting, setSubmitting] = useState(false);

  const onChange = (e) => {
    const { name, value } = e.target;
    setValues((v) => ({ ...v, [name]: value }));
    if (fieldErrors[name]) setFieldErrors((f) => ({ ...f, [name]: undefined }));
  };

  const onSubmit = async (e) => {
    e.preventDefault();
    setFormError(null);

    const errors = validateRegisterForm(values);
    setFieldErrors(errors);
    if (Object.keys(errors).length) return;

    setSubmitting(true);
    try {
      await register(values);
      // On success the session is set and the route guard moves us to /vault.
    } catch (err) {
      if (err.code === ERROR_CODES.EMAIL_TAKEN) {
        setFieldErrors({ email: err.message || 'An account with this email already exists.' });
      } else {
        setFormError(err.message || 'Something went wrong. Please try again.');
      }
      setSubmitting(false);
    }
  };

  return (
    <AuthLayout
      title="Create your vault"
      subtitle="It takes a minute. Your password never leaves this device."
      footer={<>Already have an account? <Link to="/login">Sign in</Link></>}
    >
      {formError && <Alert variant="error">{formError}</Alert>}

      <form onSubmit={onSubmit} noValidate>
        <TextField
          label="Your name"
          name="displayName"
          autoComplete="name"
          value={values.displayName}
          onChange={onChange}
          error={fieldErrors.displayName}
          autoFocus
        />
        <TextField
          label="Email"
          name="email"
          type="email"
          autoComplete="email"
          value={values.email}
          onChange={onChange}
          error={fieldErrors.email}
        />
        <PasswordField
          label="Password"
          name="password"
          autoComplete="new-password"
          value={values.password}
          onChange={onChange}
          error={fieldErrors.password}
          hint={`At least ${PASSWORD_MIN_LENGTH} characters. A few random words works well.`}
        >
          <PasswordStrengthMeter password={values.password} />
        </PasswordField>
        <PasswordField
          label="Confirm password"
          name="confirmation"
          autoComplete="new-password"
          value={values.confirmation}
          onChange={onChange}
          error={fieldErrors.confirmation}
        />

        <Alert variant="warning" title="Don't lose this password">
          Access Vault can't reset it. Because your files are encrypted with it, a lost password
          means your files can't be recovered by anyone.
        </Alert>

        <Button type="submit" loading={submitting}>
          {submitting ? 'Creating your vault…' : 'Create account'}
        </Button>
      </form>
    </AuthLayout>
  );
}
