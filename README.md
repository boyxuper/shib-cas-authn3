#### shib-oauth
修改 cas 插件以支持 OAuth 对接。

此插件只能支持 shibboleth 3.4.3 以下版本。

配置所需附件可以从 release 中或者点此[下载](https://github.com/shanghai-edu/shib-cas-authn3/releases/download/3.2.4-oauth/3.2.4-oauth-bundle.zip)

#### 具体配置
##### 新建文件夹，获取并拷贝相关文件：

```
[root@www ~]# wget https://github.com/shanghai-edu/shib-cas-authn3/releases/tag/3.2.4-oauth
[root@www ~]# unzip 3.2.4-oauth-bundle.zip
[root@www ~]# mkdir /opt/shibboleth-idp/flows/authn/Shiboauth2
```


​        把附件中shibcas-authn-beans.xml、shibcas-authn-flow.xml放入文件夹中。

​        把附件中的no-conversation-state.jsp放入/opt/shibboleth-idp/edit-webapp中。

​        把附件中的shib-cas-authenticator-3.2.4-oauth.jar、cas-client-core-3.4.1.jar放入/opt/shibboleth-idp/edit-webapp/WEB-INF/lib中。

​        如shibboleth路径为默认（/opt/shibboleth-idp），可以在附件根目录使用如下命令

```
cp shibcas-authn-beans.xml /opt/shibboleth-idp/flows/authn/Shiboauth2/shibcas-authn-beans.xml

cp shibcas-authn-flow.xml /opt/shibboleth-idp/flows/authn/Shiboauth2/shibcas-authn-flow.xml

cp no-conversation-state.jsp /opt/shibboleth-idp/edit-webapp/no-conversation-state.jsp

cp shib-cas-authenticator-3.2.4-oauth.jar /opt/shibboleth-idp/edit-webapp/WEB-INF/lib/shib-cas-authenticator-3.2.4.jar

cp cas-client-core-3.4.1.jar /opt/shibboleth-idp/edit-webapp/WEB-INF/lib/cas-client-core-3.4.1.jar
```

##### 配置web.xml：

```
[root@www ~]# cp /opt/shibboleth-idp/dist/webapp/WEB-INF/web.xml /opt/shibboleth-idp/edit-webapp/WEB-INF/web.xml
[root@www ~]# vi /opt/shibboleth-idp/edit-webapp/WEB-INF/web.xml

# 在<!-- Servlets and servlet mappings -->后加上

<!-- Servlet for receiving a callback from an external CAS Server and continues the IdP login flow -->
     <servlet>
         <servlet-name> ShibOauth2 Auth Servlet</servlet-name>
         <servlet-class>net.unicon.idp.externalauth.ShibcasAuthServlet</servlet-class>
         <load-on-startup>2</load-on-startup>
     </servlet>
     <servlet-mapping>
         <servlet-name> ShibOauth2 Auth Servlet</servlet-name>
         <url-pattern>/Authn/ExtOauth2/*</url-pattern>
     </servlet-mapping>
```

##### 配置idp.properties：
```
[root@www ~]# vi /opt/shibboleth-idp/conf/idp.properties
```

```
# 修改

idp.authn.flows = Shiboauth2

# 新增

shibcas.oauth2UrlPrefix = http://xxx.xxx.xxx.xxx #OAuth2服务器域名
shibcas.oauth2LoginUrl = ${shibcas.oauth2UrlPrefix}/xxx?response_type=code&client_id=xxx&state=xyz #OAuth2认证页面以及需要传递的参数，state可以配置成任意字符串
shibcas.serverName = https://xxx.xxx.xxx.xxx #IdP的域名
shibcas.oauth2TokenUrl = http://xxx.xxx.xxx.xxx/xxx # OAuth2用code获取token的URL
shibcas.oauth2ResourceUrl = http://xxx.xxx.xxx.xxx/xxx # OAuth2用token获取资源的URL
shibcas.oauth2clientid = testclient
shibcas.oauth2clientsecret = testpass
shibcas.oauth2redirecturi = https://xxx.xxx.xxx/idp/Authn/ExtOauth2?conversation=e1s1

# 新增

shibcas.oauth2redirecturiBase = https://xxx.xxx.xxx.xxx/idp/Authn/ExtOauth2
shibcas.oauth2principalname =  uid # oauth 释放属性中，作为用户名输入的那个字段。这个字段必须存在，不然会报错
```

##### 配置general-authn.xml：

```
[root@www ~]# vi /opt/shibboleth-idp/conf/authn/general-authn.xml

# 在<util:list id="shibboleth.AvailableAuthenticationFlows">后新增

<bean id="authn/Shiboauth2" parent="shibboleth.AuthenticationFlow"
                 p:passiveAuthenticationSupported="true"
                 p:forcedAuthenticationSupported="true"
                 p:nonBrowserSupported="false" />
```

##### 配置属性释放
`xsi:type="SubjectDerivedAttribute"` 为从插件中获取属性的配置，例如下面的示例表示，从 OAuth 中获取的 role 属性，映射为 shibboleth 中的 eduPersonScopedAffiliation

```
<?xml version="1.0" encoding="UTF-8"?>
<AttributeResolver
         xmlns="urn:mace:shibboleth:2.0:resolver"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" 
         xsi:schemaLocation="urn:mace:shibboleth:2.0:resolver http://shibboleth.net/schema/idp/shibboleth-attribute-resolver.xsd">

   <AttributeDefinition xsi:type="SubjectDerivedAttribute" id="eduPersonScopedAffiliation" principalAttributeName="role" >
        <AttributeEncoder xsi:type="SAML1String" name="urn:mace:dir:attribute-def:eduPersonScopedAffiliation" encodeType="false" />
        <AttributeEncoder xsi:type="SAML2String" name="urn:oid:1.3.6.1.4.1.5923.1.1.1.9" friendlyName="eduPersonScopedAffiliation" encodeType="false" />
   </AttributeDefinition>

</AttributeResolver>
```

##### 重新编译war文件，并且重启tomcat：

```
[root@www ~]# cd /opt/shibboleth-idp/bin
[root@www ~]# ./build.sh

Installation Directory: [/opt/shibboleth-idp] #enter

Rebuilding /opt/shibboleth-idp/war/idp.war ...

...done

BUILD SUCCESSFUL

Total time: 3 seconds

[root@www ~]# systemctl restart tomcat
```

