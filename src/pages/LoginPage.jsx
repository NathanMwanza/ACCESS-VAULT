import { useState } from 'react';
import { Link } from 'react-router-dom';
import AuthLayout from '../components/AuthLayout.jsx';
import TextField from '../components/TextField.jsx';
import PasswordField from '../components/PasswordField.jsx';
import Button from '../components/Button.jsx';
import Alert from '../components/Alert.jsx';
import { useAuth } from '../context/AuthContext.jsx';
import { validateLoginForm } from '../utils/validation.js';
import { ERROR_CODES } from '../services/contract.js';

export default function LoginPage() {
  const { login, notice } = useAuth();

  const [values, setValues] = useState({ email: '', password: '' });
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

    const errors = validateLoginForm(values);
    setFieldErrors(errors);
    if (Object.keys(errors).length) return;

    setSubmitting(true);
    try {
      await login(values);
      // On success the session is set and the route guard moves us to /vault.
    } catch (err) {
      // invalid_credentials is deliberately generic: never reveal which field was wrong (Table 4.10).
      if (err.code === ERROR_CODES.INVALID_CREDENTIALS) {
        setFormError('Incorrect email or password.');
      } else {
        setFormError(err.message || 'Something went wrong. Please try again.');
      }
      setSubmitting(false);
    }
  };

  return (
    <AuthLayout
      title="Welcome back"
      subtitle="Sign in to unlock your vault."
      footer={<>New to Access Vault? <Link to="/register">Create an account</Link></>}
    >
      {notice === 'signed_out' && <Alert variant="info">You have been signed out.</Alert>}
      {formError && <Alert variant="error">{formError}</Alert>}

      <form onSubmit={onSubmit} noValidate>
        <TextField
          label="Email"
          name="email"
          type="email"
          autoComplete="email"
          value={values.email}
          onChange={onChange}
          error={fieldErrors.email}
          autoFocus
        />
        <PasswordField
          label="Password"
          name="password"
          autoComplete="current-password"
          value={values.password}
          onChange={onChange}
          error={fieldErrors.password}
        />
        <Button type="submit" loading={submitting}>
          {submitting ? 'Unlocking…' : 'Sign in'}
        </Button>
      </form>
    </AuthLayout>
  );
}
