//
//  KeychainHelper.swift
//  KeychainWrapper
//
//  Created by Madhubhai.IOS on 31/07/24.
//

import Foundation
import Security

enum KeyOperation {
    case save
    case update
    case delete
}

class KeychainHelper {
    
    /// Saves data to the Keychain with the specified key.
    /// - Parameters:
    ///   - key: The key used to identify the data in the Keychain.
    ///   - data: The data to be saved.
    /// - Returns: A Boolean value indicating whether the data was saved successfully.
    class func save(key: String, data: Data) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecValueData as String: data
        ]
        
        SecItemDelete(query as CFDictionary) // Delete any existing item
        let status = SecItemAdd(query as CFDictionary, nil)
        
        return status == errSecSuccess
    }
    
    /// Loads data from the Keychain with the specified key.
    /// - Parameter key: The key used to identify the data in the Keychain.
    /// - Returns: The data associated with the key, or nil if the data could not be found.
    class func load(key: String) -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecReturnData as String: kCFBooleanTrue!,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        
        var dataTypeRef: AnyObject? = nil
        let status = SecItemCopyMatching(query as CFDictionary, &dataTypeRef)
        
        if status == errSecSuccess {
            return dataTypeRef as? Data
        } else {
            return nil
        }
    }
    
    /// Deletes data from the Keychain with the specified key.
    /// - Parameter key: The key used to identify the data in the Keychain.
    /// - Returns: A Boolean value indicating whether the data was deleted successfully.
    class func delete(key: String) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key
        ]
        
        let status = SecItemDelete(query as CFDictionary)
        
        return status == errSecSuccess
    }
    
    /// Generates a new RSA key pair.
    /// - Returns: A tuple containing the private and public keys, or nil if key generation fails.
    class func generateKeyPair() -> (privateKey: SecKey?, publicKey: SecKey?) {
        var error: Unmanaged<CFError>?
        
        let privateKeyAttr: [String: Any] = [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: "com.example.privatekey"
        ]
        
        let keyPairAttr: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: 2048,
            kSecPrivateKeyAttrs as String: privateKeyAttr
        ]
        
        guard let privateKey = SecKeyCreateRandomKey(keyPairAttr as CFDictionary, &error) else {
            print("Key pair generation failed: \(error!.takeRetainedValue() as Error)")
            return (nil, nil)
        }
        
        let publicKey = SecKeyCopyPublicKey(privateKey)
        
        return (privateKey, publicKey)
    }
    
    /// Stores the private key in the Keychain.
    /// - Parameter privateKey: The private key to be stored.
    /// - Returns: A Boolean value indicating whether the private key was stored successfully.
    class func storePrivateKey(privateKey: SecKey) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: "com.example.privatekey",
            kSecValueRef as String: privateKey,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlocked
        ]
        
        SecItemDelete(query as CFDictionary) // Delete any existing item
        let status = SecItemAdd(query as CFDictionary, nil)
        
        return status == errSecSuccess
    }
    
    /// Retrieves the private key from the Keychain.
    /// - Returns: The private key if it exists, or nil if retrieval fails.
    class func retrievePrivateKey() -> SecKey? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: "com.example.privatekey",
            kSecReturnRef as String: kCFBooleanTrue!
        ]
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        
        guard status == errSecSuccess else {
            print("Failed to retrieve private key: \(status)")
            return nil
        }
        
        return (item as! SecKey)
    }
    
    /// Retrieves the public key from the Keychain.
    /// - Returns: The public key if it exists, or nil if retrieval fails.
    class func retrievePublicKey() -> SecKey? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: "com.example.publickey",
            kSecReturnRef as String: kCFBooleanTrue!
        ]
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        
        guard status == errSecSuccess else {
            print("Failed to retrieve public key: \(status)")
            return nil
        }
        
        return (item as! SecKey)
    }
    
    /// Encrypts data using the specified public key.
    /// - Parameters:
    ///   - data: The data to be encrypted.
    ///   - publicKey: The public key used for encryption.
    /// - Returns: The encrypted data, or nil if encryption fails.
    class func encrypt(data: Data, using publicKey: SecKey) -> Data? {
        var error: Unmanaged<CFError>?
        let encryptedData = SecKeyCreateEncryptedData(publicKey, .rsaEncryptionPKCS1, data as CFData, &error) as Data?
        
        if let error = error {
            print("Encryption error: \(error.takeRetainedValue() as Error)")
            return nil
        }
        
        return encryptedData
    }
    
    /// Decrypts data using the specified private key.
    /// - Parameters:
    ///   - data: The data to be decrypted.
    ///   - privateKey: The private key used for decryption.
    /// - Returns: The decrypted data, or nil if decryption fails.
    class func decrypt(data: Data, using privateKey: SecKey) -> Data? {
        var error: Unmanaged<CFError>?
        let decryptedData = SecKeyCreateDecryptedData(privateKey, .rsaEncryptionPKCS1, data as CFData, &error) as Data?
        
        if let error = error {
            print("Decryption error: \(error.takeRetainedValue() as Error)")
            return nil
        }
        
        return decryptedData
    }
    
    /// Manages a cryptographic key by saving, updating, or deleting it in the Keychain.
    /// - Parameters:
    ///   - keyData: The data of the key to be managed.
    ///   - tag: The tag associated with the key in the Keychain.
    ///   - operation: The operation to be performed (save, update, or delete).
    /// - Returns: A Boolean value indicating whether the operation was successful.
    class func manageKey(_ keyData: Data?, withTag tag: String, operation: KeyOperation) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag.data(using: .utf8)!
        ]
        
        switch operation {
        case .save:
            guard let keyData = keyData else { return false }
            var saveQuery = query
            saveQuery[kSecValueData as String] = keyData
            saveQuery[kSecAttrKeyType as String] = kSecAttrKeyTypeEC
            
            let status = SecItemAdd(saveQuery as CFDictionary, nil)
            return status == errSecSuccess
            
        case .update:
            guard let keyData = keyData else { return false }
            let attributes: [String: Any] = [kSecValueData as String: keyData]
            
            let status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
            return status == errSecSuccess
            
        case .delete:
            let status = SecItemDelete(query as CFDictionary)
            return status == errSecSuccess
        }
    }
    
    /// Loads a cryptographic key from the Keychain with the specified tag.
    /// - Parameter tag: The tag associated with the key in the Keychain.
    /// - Returns: The data of the key if it exists, or nil if retrieval fails.
    class func loadKey(withTag tag: String) -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag.data(using: .utf8)!,
            kSecReturnData as String: kCFBooleanTrue!,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        
        guard status == errSecSuccess, let data = item as? Data else {
            return nil
        }
        
        return data
    }
}

