import { NativeModules } from 'react-native'

function validate(cert) {
  return NativeModules.TCertChecker.validateCertificate(cert)
}

export default validate
