# ServiceStorage

A NAS managing dir structure with filesystem and store objects with S3

## Features
1. High throughput : Thanks to S3.  
2. Versioning  : Important feature.  
3. Access Control : CRUD x private/link/account white list/... which can be easily integrated with other modules  

## Behavior  
1. Transaction : Not supported due to the strategy of consistency / concurrency, users should maintain on their own ( like disallow multiple sessions of the same account which may modify the same object )  
2. Duplicated filename : Duplicated filename is force allowed, we use the Object Name as an unique identifier.  
3. Directory : Directory is implemented.  
4. Download : Currently we only support download single file. If you'd like to download the whole directory, you should handle it with your client, such as maintaining the file tree and handle duplicated dirname / filename.  


## Lifetime of Object
1. Create  
2. Modify / Upload New Version  
3. Delete

Once the Object has been marked deleted, even their was an ongoing Modify / Upload New Version operation successfully performed to S3 after the Delete operation, such object is still marked deleted.  

## Upload Object  
1. (Client) Ask NAS for all the subdir's Object Name (because we may got duplicated dirname)  
2. (NAS) Authorize & response.  
3. (Client) Ask NAS for S3 upload dst.  
4. (NAS) Authorize the request.  
5. (NAS) Generate a presignedPOST.  
6. (NAS) Modify the filetree. 
6. (NAS) (TODO) Add the S3  upload dst to the DynamoDB table `ongoing` with the same expired time as presignedPOST.  
7. (Client) Perform upload to S3.  
9. (Client) Tell NAS you've done uploading.  
10. (NAS) Modify the filetree
11. (NAS) (TODO) delete the record in table `ongoing`.  

## Hard Limitation  
1. Concurrency  

if User A and user B List the tree as below  
```
root - dirA - a.txt  
    \- dirB - b.txt  
```
User A moves b.txt to dirA, and User B deletes dirA  
It's possible that both success  
```
root - (deleted) dirA - a.txt
   \- dirB           \- b.txt
```
Which means, User B doesn't know he just deleted the b.txt inside dirA  
The Application should handle this on its own.  
## Q&As
1.  
    Q : Why don't we use Cognito?  
    A : Flexibility & pricing(if we validate every request, $0.0055 MAU is not a good deal, especially if developers take this service as a module, they may already have their own account management system)  
