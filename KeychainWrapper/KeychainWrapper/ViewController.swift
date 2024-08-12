//
//  ViewController.swift
//  KeychainWrapper
//
//  Created by 200Ok.IOS on 31/07/24.
//

import UIKit
import CryptoKit

struct UserDetails: Codable {
    let username: String
    let password: Data
}

class ViewController: UIViewController {

    /// Called after the controller's view is loaded into memory.
    override func viewDidLoad() {
        super.viewDidLoad()
        
        // Manage the CryptoKit key by performing save, load, update, and delete operations.
        manageCryptoKey()

        // Example usage of generating a key pair and saving user details.
        let keyPair = KeychainHelper.generateKeyPair()
        if let privateKey = keyPair.privateKey, let publicKey = keyPair.publicKey {
            print("Key pair generated successfully")
            
            // Example user credentials.
            let username = "exampleUser"
            let password = "examplePass"
            
            // Save user details using the public key for encryption.
            if saveUserDetails(username: username, password: password, publicKey: publicKey) {
                print("User details saved successfully")
                
                // Load user details using the private key for decryption.
                if let loadedUserDetails = loadUserDetails(privateKey: privateKey) {
                    print("Loaded User Details: \(loadedUserDetails)")
                } else {
                    print("Failed to load user details")
                }
            } else {
                print("Failed to save user details")
            }
        } else {
            print("Failed to generate key pair")
        }
        
        //*************************  SecAccessControl **************************//
        let result = saveOrUpdateUserDetails(username: "200Ok", password: "200OK_PASSWORD")
        if(result){
            print("User details saved successfully")
        }else{
            print("Failed to save user details")
        }
        
        let password = KeychainHelper.fetchUserDetails(username: "200OK")
        print("Password for 200OK is \(password ?? "")")
        //*************************  SecAccessControl **************************//

    }

    /// Saves the user details by encrypting the password with the provided public key.
    /// - Parameters:
    ///   - username: The username to save.
    ///   - password: The password to save.
    ///   - publicKey: The public key used to encrypt the password.
    /// - Returns: A Boolean value indicating whether the user details were saved successfully.
    func saveUserDetails(username: String, password: String, publicKey: SecKey) -> Bool {
        let passwordData = password.data(using: .utf8)!
        
        // Encrypt the password using the public key.
        guard let encryptedPassword = KeychainHelper.encrypt(data: passwordData, using: publicKey) else {
            print("Failed to encrypt password")
            return false
        }
        
        // Create a UserDetails object with the encrypted password.
        let userDetails = UserDetails(username: username, password: encryptedPassword)
        
        // Encode the UserDetails object to JSON.
        do {
            let data = try JSONEncoder().encode(userDetails)
            return KeychainHelper.save(key: "userDetailsKey", data: data)
        } catch {
            print("Failed to encode user details: \(error)")
            return false
        }
    }

    /// Loads the user details by decrypting the password with the provided private key.
    /// - Parameter privateKey: The private key used to decrypt the password.
    /// - Returns: A UserDetails object if loading and decryption are successful, or nil otherwise.
    func loadUserDetails(privateKey: SecKey) -> UserDetails? {
        // Load the user details data from the Keychain.
        guard let data = KeychainHelper.load(key: "userDetailsKey") else { return nil }
        
        // Decode the JSON data to a UserDetails object.
        do {
            let userDetails = try JSONDecoder().decode(UserDetails.self, from: data)
            
            // Decrypt the password using the private key.
            guard let decryptedPasswordData = KeychainHelper.decrypt(data: userDetails.password, using: privateKey),
                  let password = String(data: decryptedPasswordData, encoding: .utf8) else {
                print("Failed to decrypt password")
                return nil
            }

            // Return the UserDetails object with the decrypted password.
            return UserDetails(username: userDetails.username, password: password.data(using: .utf8)!)
        } catch {
            print("Failed to decode user details: \(error)")
            return nil
        }
    }

    
    /// Manages a CryptoKit key by saving, loading, updating, and deleting it using KeychainHelper.
    func manageCryptoKey() {
        
        // Generate a new symmetric key.
        let key = SymmetricKey(size: .bits256)
        
        // Convert the key to Data.
        let keyData = key.withUnsafeBytes { Data(Array($0)) }
        
        // Define a tag for the key.
        let tag = "com.example.mykey"

        // Save the key to the Keychain.
        if KeychainHelper.manageKey(keyData, withTag: tag, operation: .save) {
            print("Key saved successfully")
        }

        // Load the key from the Keychain.
        if let loadedKeyData = KeychainHelper.loadKey(withTag: tag) {
            let loadedKey = SymmetricKey(data: loadedKeyData)
            print("Key loaded successfully")
        }

        // Generate a new symmetric key for updating.
        let newKey = SymmetricKey(size: .bits256)
        
        // Convert the new key to Data.
        let newKeyData = newKey.withUnsafeBytes { Data(Array($0)) }

        // Update the key in the Keychain.
        if KeychainHelper.manageKey(newKeyData, withTag: tag, operation: .update) {
            print("Key updated successfully")
        }

        // Delete the key from the Keychain.
        if KeychainHelper.manageKey(nil, withTag: tag, operation: .delete) {
            print("Key deleted successfully")
        }
    }
    
    //****************************** USE OF SecAccessControl *****************************//
    
    // Saves or updates user details (username and password) in the Keychain.
    func saveOrUpdateUserDetails(username: String, password: String) -> Bool {
        // Define the search query to locate the existing Keychain item.
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,  // Look for generic passwords.
            kSecAttrAccount as String: username,             // Match the account attribute.
            kSecAttrService as String: "com.example.myapp"  // Match the service attribute.
        ]
        
        // Define the attributes to update for the existing Keychain item (e.g., the password).
        let attributesToUpdate: [String: Any] = [
            kSecValueData as String: password.data(using: .utf8)!, // New password data.
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlocked // Update accessibility.
        ]

        // Attempt to update the existing Keychain item.
        let updateStatus = SecItemUpdate(query as CFDictionary, attributesToUpdate as CFDictionary)

        if updateStatus == errSecSuccess {
            // If the update was successful, print a message and return true.
            print("User details updated successfully")
            return true
        } else if updateStatus == errSecItemNotFound {
            // If the item does not exist, proceed to add a new item.
            print("Item not found, adding new item")

            var addStatus: OSStatus
            if let accessControl = KeychainHelper.createAccessControl() {
                // Create a new Keychain item with access control.
                let userDetails: [String: Any] = [
                    kSecClass as String: kSecClassGenericPassword,  // Define the Keychain item class.
                    kSecAttrAccount as String: username,             // Account attribute.
                    kSecAttrService as String: "com.example.myapp",  // Service attribute.
                    kSecValueData as String: password.data(using: .utf8)!, // Password data.
                    kSecAttrAccessControl as String: accessControl   // Access control object.
                ]
                addStatus = SecItemAdd(userDetails as CFDictionary, nil)
            } else {
                // Create a new Keychain item without access control.
                addStatus = SecItemAdd(query as CFDictionary, nil)
            }

            if addStatus == errSecSuccess {
                // If the addition was successful, print a message and return true.
                print("User details saved successfully")
                return true
            } else {
                // If there was an error adding the new item, print the error status and return false.
                print("Error saving user details: \(addStatus)")
                return false
            }
        } else {
            // If there was an error updating the item, print the error status and return false.
            print("Error updating user details: \(updateStatus)")
            return false
        }
    }

}

