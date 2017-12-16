import { NativeModules } from 'react-native'

function validate(cert) {
  const native = NativeModules.TCertChecker
  if (!native) {
    return Promise.reject('Native module TCertChecher not found. May be you need react-native link.')
  }
  return native.validateCertificate(cert)
}

export default validate
