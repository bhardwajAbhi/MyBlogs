---
title: Secure Coding Practices
description: Coding practices that a developer need to follow in order to design and implement robust, rugged, and secure apps for Android device.
banner: 10_what_is_mobile_sec.png
date: 2022-10-13
tags:
    - secure coding, secure coding practices, android security, android best practices
---


## Introduction

With the Android platform fast becoming a target of malicious hackers, applications security is no longer an add-on, but a crucial part of the developer’s job.

This post provides secure coding practices that a developer need to follow in order to design and implement robust, rugged, and secure apps for Android device.


## 1. Verify for Security Early and Often

### Securing Application Components

- Application Components are the essential building blocks of an Android Application.

- Each component is an entry point through which the system or a user can enter your application.

- Four major Android Application Components are: 
    - Activities
    - Services
    - Content Providers
    - Broadcast Receivers

- One of the common mistakes while developing applications is unintentionally leaving application components exposed.

- Application components can be secured both by making proper use of the ==**AndroidManifest.xml**== file and by forcing permission checks at code level.

- These two factors of application security make the permissions framework quite flexible and allow you to limit the number of applications accessing your components in quite a granular way.

- The ==**android:exported**== attribute defines whether a component can be invoked by other applications.

- If any of your application components do not need to be invoked by other applications or need to be explicitly shielded from interaction with the components on the rest of the Android system (other than components internal to your application)

- You should add the following attribute to the application component's XML element:

``` java title="AndroidManifest.xml" linenums="1" hl_lines="1"
<[component-name] android:exported="false">
...
</[component-name]>
```

- Here the [component name] would either be an activity, provider, service or a receiver.

### Protecting components with Custom Permissions

- The Android platform defines a set of default permissions which are used to secure system services and application components.

- Largely, these permissions work in the most generic case, but often when sharing bespoke functionality or components between applications it will require a more tailored use of the permissions framework.

- **This is facilitated by defining custom permissions**.

___

**Following snippets demonstrates how you can define your own custom permissions**:

1. Before adding any custom permissions, you need to declare string resources for the permission labels. You can do this by editing the strings.xml file in your application project folder under ==**res/values/strings.xml**==:
``` java title="res/values/strings.xml" linenums="1"
<string name="custom_permission_label">Custom Permission</string>
```

2. Adding normal protection-level custom permissions to your application can be done by adding the following lines to your ==**AndroidManifest.xml**== file:
``` java title="AndroidManifest.xml" linenums="1"
<permission android:name="android.permission.CUSTOM_PERMISSION"
android:protectionLevel="normal"
android:description="my custom permission"
android:label="@string/custom_permission_label">
```

3. Making use of this permission works the same as any other permission; you need to add it to the ==**android:permission**== attribute of an application component.
``` java title="AndroidManifest.xml" linenums="1"
<[component-name] ...
    android:permission="android.permission.CUSTOM_PERMISSION">
</[component-name]>
```
Here the [component name] would either be an activity, provider, service or a receiver.

4. You can also allow other applications to request this permission by adding the ==**\<uses-permission/>**== tag to an application's AndroidManifest.xml file:
``` java title="AndroidManifest.xml" linenums="1"
<uses-permission android:name="android.permission.CUSTOM_PERMISSION"/>
```

**The breakdown of the attributes of ==**\<permission>**== element is as follows**:

- **android:name** - This defines the name of the permissions, which is the string value that will be used to reference this permission.

- **android:protectionLevel** - This defines the protection level of the permission and controls whether users will be prompted to grant the permission. Following are the Protection Levels:
    - **normal** -  This permission is used to define non dangerous permissions, these permissions will not be prompted and may be granted autonomously.
    
    - **dangerous** - This permission is used to define permissions that expose the user to considerable fiscal, reputational, and legal risk.

    - **signature** -  This permission is granted autonomously to applications that are signed with the same key as the application that defines them.
    
    - **signatureOrSystem** - This permission is automatically granted to any application that forms a part of the system image or is signed with the same key as the application that defines them.



## 2. Parameterized Queries

### SQL Injection

- One specific form of a class of vulnerabilities known as command injection.

- In this type of vulnerability, input from an outside source is used directly as part of a command, in this case a SQL expression that is passed to a database interpreter.

**For Example:**

- consider a case where the user supplies a username and password to an application, which must then verify that the combination is valid to allow access.
``` java linenums="1"
String loginQuery = "SELECT * FROM useraccounts WHERE userID = '" + request.getParameter("userID") + "' AND password = '" + request.getParameter("password") + "'";
```

- However, if whoever is submitting the information were to submit these values:
``` java linenums="1" 
userID = ' or 1=1 --
password = doesNotMatter
```

- The resulting query that would be supplied to the SQL database interpreter would be:
``` java linenums="1" 
SELECT * FROM useraccounts WHERE userID='' or 1=1 -- AND password='doesNotMatter'
```
This SQL statement would then evaluate and return all of the data from the user accounts table, as the WHERE condition would always be true (due to the OR 1=1 condition) and the password checking clause would be commented out.

___

**This unintended behavior is made possible because of two primary problems.**

- **First**, our app did not properly validate the input that was received before using that input to form the SQL statement to be submitted to the database interpreter.

- **Second**, the problem is enabled because when query strings are constructed in such a manner, the database system cannot tell the difference between code and data; the initial apostrophe ==(')== submitted in the *userID* is actually data, but is being interpreted as code because the database cannot tell that it should be interpreted as a literal data value.

### Preventing Command Injection

- Looking at an example similar to the earlier one.

- Let's consider looking up a user’s last name in a database. The unsafe way to form this statement looks something like this:
``` java linenums="1" 
SQLiteDatabase db = dbHelper.getWriteableDatabase();
String userQuery = "SELECT lastName FROM useraccounts WHERE userID = " + request.getParameter("userID");
String userLastName = prepStatement.simpleQueryForString();
```

- Here is the proper way to perform such a query against the database, where the command is separated from the data:
``` java linenums="1" 
SQLiteDatabase db = dbHelper.getWriteableDatabase();
String userQuery = "SELECT lastName FROM useraccounts WHERE userID = ?";
SQLiteStatement prepStatement = db.compileStatement (userQuery);
prepStatement.bindString(1, request.getParameter("userID")); 
String userLastName = prepStatement.simpleQueryForString();
```

By taking advantage of the **compileStatement** capability, we can effectively separate commands from data in SQL statements, by using the ==**?**== marker. This is known as a parameterized query, as the query string includes placeholders ==(question marks)== to mark the data and the values for those pieces of data are filled in independently (by the bindString() call in our example).


## 3. Encode Data

- Encoding your data is a solution you should consider if you work with slightly less sensitive data or are looking for a way to organize your data.

- Most encoding methods rely on algorithms to compress the data and reduce its complexity.

- The same algorithm used to encode the data is needed to access the data in a readable format.

- Encoding keeps your data safe since the data is not readable unless you have access to the algorithms that were used to encode it.

- This is a good way to protect your data from theft since any stolen data would not be usable.

- Encoding is an ideal solution if you need to have third parties access your data but do not want to have everyone be able to access some sensitive data.

- Since encoding removes redundancies from data, the size of your data will be a lot smaller.

- This results in faster input speed when data is processed or saved.
Since encoded data is smaller in size, you should be able to save space on your storage devices.

- Encoded data is easy to organize, even if the original data was mostly unstructured.

- This is how we can encode a normal string to a Base64 encoding scheme.
``` java linenums="1" 
String testValue = "Hello, world!";

byte[] encodeValue = Base64.encode(testValue.getBytes(), Base64.DEFAULT);
byte[] decodeValue = Base64.decode(encodeValue, Base64.DEFAULT);

Log.d("ENCODE_DECODE", "defaultValue = " + testValue);
Log.d("ENCODE_DECODE", "encodeValue = " + new String(encodeValue));
Log.d("ENCODE_DECODE", "decodeValue = " + new String(decodeValue));
```
``` java title="Output" linenums="1" 
defaultValue = Hello, world!
encodeValue = SGVsbG8sIHdvcmxkIQ==
decodeValue = Hello, world!
```

## 4. Validate All Inputs

!!! hint " "

    Coming Soon


## 5. Implement Identity and Authentication Controls

- Providing a secure login mechanism for your users is harder than on the Web.

- The trend on mobile devices is to make things as easy as possible for the user.

- But if you make it too easy to login into your app, you run the risk of unauthorized users gaining access to sensitive data by going around this authentication.

- The following tokens are common on Android devices as a part of login process:
    - Username and Password
    - Device information, such as DeviceID and AndroidID
    - Network information, such as IP address

- The classic login of username and password is still the most common authentication on an Android phone.

- Let’s look at some best practices for user authentication. 

- The best practices are as follows:
    - No password caching
    - Minimum password length
    - Multi-factor authentication
    - Server-side as well as client-side authentication

- Do not save or cache username, and especially password, information on the phone, as there is always a risk that it will be found and decrypted. 

- Even if you’re encrypting the password, if you’re also storing the key in the APK then it’s going to be unencrypted.

- It is better not to store passwords, if you can get away with it, and make the user Log In each time.

- **Try to enforce a minimum password length** - passwords of less than six characters are highly prone to a brute force attack. Financial apps should have stricter policies than other apps.

- **Validate email addresses** - this can be done either using regular expressions or via an email link during setup or, better still, using both approaches.

- If you do update your password standards, notify your existing customers when they login again to update their passwords.

- It’s becoming very common for applications to use a **Two-Factor Authentication** where a randomly generated PIN number is sent via SMS message to user’s phone before he can log in to the application. 

- We can also use the info like DeviceID, IP Address, and Location information to add extra layers of information.

- **Access control** doesn’t end at the client; it needs to be enforced at the server, too. 

- Some back-end servers mistakenly rely on the client app to perform all authentication and assume that the web server doesn’t need to do any authentication.

- The server should also check for valid credentials each time or use a session token once again over SSL.

- It should also check for unusual activity, such as someone performing a bruteforce attack, and notify the user via email of unusual login activity.

- If you are saving any personal, healthcare, or financial information, you should use an **asymmetric** or **public/private** key. 

- This does require a round trip back to the server to decrypt the data, but if the phone is compromised, the user’s data will remain secure.

- Only the private key can decrypt the data, and that should never be stored on the phone.

## 6. Cryptographically Secure Data

!!! hint " "

    Coming Soon

## 7. Implement Logging and Intrusion Detection

!!! hint " "

    Coming Soon

## 8. Leverage Security Frameworks and Libraries

!!! hint " "

    Coming Soon

## 9. Monitor Error and Exception Handling

!!! hint " "

    Coming Soon

## 10. Handling Intents

!!! hint " "

    Coming Soon

