---
lab:
    title: '演習 9 - ASIM パーサーの作成'
    module: 'モジュール 7 - Microsoft Sentinel を使用した検出の作成と調査の実行'
---

# モジュール 7 - ラボ 1 - 演習 9 - ASIM パーサーの作成

## ラボのシナリオ

あなたは、Microsoft Sentinelを実装した会社で働くセキュリティ運用アナリストです。特定の Windows レジストリー・イベント用に ASIM パーサーをモデル化する必要があります。これらの簡略化されたパーサーは、[Advanced Security Information Model (ASIM) レジストリ イベント正規化スキーマのリファレンス](https://learn.microsoft.com/ja-jp/azure/sentinel/normalization-schema-registry-event) に従って後で完成します。

>**ノート:** **[interactive lab simulation](https://mslabs.cloudguides.com/guides/SC-200%20Lab%20Simulation%20-%20Create%20Advanced%20Security%20Information%20Model%20Parsers)** このラボを自分のペースで確認できます。ホスト型のラボと多少の違いはありますが、主要な概念とアイデアは同じです。

### タスク 1: レジストリ スキーマ ASIM パーサーを展開します

このタスクでは、Microsoft Sentinel GitHub リポジトリからレジストリ スキーマ パーサーをデプロイします。

1. 管理者として WIN1 仮想マシンにログインします。パスワードは**Pa55w.rd** です。

1. Microsoft Edge ブラウザーで Azure portal (https://portal.azure.com) に移動します。

1. **サインイン** ダイアログ ボックスで、ラボ ホスティング プロバイダーから提供された**テナントの電子メール**アカウントをコピーして貼り付け、「**次へ**」を選択します。

1. **パスワードの入力**ダイアログ ボックスで、ラボ ホスティング プロバイダーから提供された**テナントパスワード** をコピーして貼り付け、「**サインイン**」を選択します。

1. Azure portal の検索バーに「**Sentinel**」と入力してから、「**Microsoft Sentinel**」を選択します。

1. 前のラボで作成した Microsoft Sentinel ワークスペースを選択します。

1.  [Microsoft Sentinel on GitHub](https://github.com/Azure/Azure-Sentinel) をコントロールキーを押しながらクリックします。Microsoft Sentinel GitHubコンテンツのページが新しいタブに表示されます。

1. ASIM フォルダーを選択します。ここでは、すべての ASIM パーサーを含むテンプレートをデプロイできますが、ここではレジストリ スキーマにのみ焦点を当てます。

1. 下にスクロールし、**Registry** の横にある **Deploy to Azure** ボタンを選択します。

1. リソース グループで、センチネル ワークスペースが存在する RG-Sentinel を選択します。

1. *Workspace* に、既存のSentinel ワークスペース名を入力します。

1. 他の既定値はそのままにして、「確認と作成」をクリックします。

1. 「作成」を選択してテンプレートをデプロイします。さまざまなリソースの名前に注目してください。

1. Azure portal の検索バーに「Sentinel」と入力し、「Microsoft Sentinel」を選択します。

1. Microsoft Sentinel ワークスペースを選択します。

1. 「全般」セクションの「ログ」を選択します。

1. 必要に応じて 「スキーマとフィルター」 ブレードを開き「>>」を選択します。

1. 「関数」タブ (「テーブル」タブと「クエリ」タブの横) を選択します。

1. 「ワースペース関数」を展開します。名前が、展開したテンプレートに対応していることに注意してください。

1. **vimRegistryEventMicrosoftWindowsEvent** ワークスペースパーサーにカーソルを合わせ、**関数コードを読み込む** を選択します。

1. イベント ID 4657 を解析している KQL を確認して、Microsoft Sentinel ワークスペース内のデータの分析を簡略化します。

1. クエリを実行します。結果もエラーも取得するべきではありません、それは検証目的のためだけです。

1. 「スキーマとフィルター」ブレードに戻り、**imRegistry** 統合パーサーにカーソルを合わせて、**関数コードを読み込む** を選択します。

1. 統合パーサーは union 演算子を使用して、すべてのワークスペース パーサーを一度に実行することに注意してください。レジストリスキーマのパーサーを開発する場合は、ここに追加する必要があります。

1. クエリを実行します。結果もエラーも取得するべきではありません、それは検証目的のためだけです。

1. この統合パーサーは、分析ルールまたはハンティング クエリに使用できるようになりました。


## 演習 10 に進みます。




























<!--
### タスク 1: Microsoft 365 Defender レジストリイベントの KQL 関数を開発する

このタスクでは、DeviceRegistryEvents のワークスペース パーサーである関数を作成します。

1. 管理者として WIN1 仮想マシンにログインします。パスワードは**Pa55w.rd** です。  

1. Microsoft Edge ブラウザーで Azure portal (https://portal.azure.com) に移動します。

1. **サインイン** ダイアログ ボックスで、ラボ ホスティング プロバイダーから提供された**テナントのメール** アカウントをコピーして貼り付け、「**次へ**」を選択します。

1. **パスワードの入力**ダイアログ ボックスで、ラボ ホスティング プロバイダーから提供された**テナントパスワード** をコピーして貼り付け、「**サインイン**」を選択します。

1. Azure portal の検索バーに「*Sentinel*」と入力してから、「**Microsoft Sentinel**」を選択します。

1. Microsoft Sentinel ワークスペースを選択します。

1. 「**ログ**」を選択する 

1. 新規クエリ1のスペースに以下のKQLステートメントを入力します。

    ```KQL
    let RegistryType = datatable (TypeCode: string, TypeName: string) [
    "None", "Reg_None",
    "String", "Reg_Sz",
    "ExpandString", "Reg_Expand_Sz",
    "Binary", "Reg_Binary",
    "Dword", "Reg_DWord",
    "MultiString", "Reg_Multi_Sz",
    "QWord", "Reg_QWord"
    ];
    let RegistryEvents_M365D=() {
    DeviceRegistryEvents
    | extend
        // Event
        EventOriginalUid = tostring(ReportId),
        EventCount = int(1), 
        EventProduct = 'M365 Defender for Endpoint',
        EventVendor = 'Microsoft', 
        EventSchemaVersion = '0.1.0', 
        EventStartTime = TimeGenerated, 
        EventEndTime = TimeGenerated, 
        EventType = ActionType,
        // Registry
        RegistryKey = iff (ActionType in ("RegistryKeyDeleted", "RegistryValueDeleted"), PreviousRegistryKey, RegistryKey),
        RegistryValue = iff (ActionType == "RegistryValueDeleted", PreviousRegistryValueName, RegistryValueName),
        // RegistryValueType -- original name is fine
        // RegistryValueData -- original name is fine
        RegistryKeyModified = iff (ActionType == "RegistryKeyRenamed", PreviousRegistryKey, ""),
        RegistryValueModified = iff (ActionType == "RegistryValueSet", PreviousRegistryValueName, ""),
        // RegistryValueTypeModified -- Not provided by Defender
        RegistryValueDataModified = PreviousRegistryValueData
    | lookup RegistryType on $left.RegistryValueType == $right.TypeCode
    | extend RegistryValueType = TypeName
    | project-away
        TypeName,
        PreviousRegistryKey,
        PreviousRegistryValueName,
        PreviousRegistryValueData
    // Device
    | extend
        DvcHostname = DeviceName,
        DvcId = DeviceId,
        Dvc = DeviceName
    // Users
    | extend
        ActorUsername = iff (InitiatingProcessAccountDomain == '', InitiatingProcessAccountName, strcat(InitiatingProcessAccountDomain, '\\', InitiatingProcessAccountName)), 
        ActorUsernameType = iff(InitiatingProcessAccountDomain == '', 'Simple', 'Windows'), 
        ActorUserIdType = 'SID'
    | project-away InitiatingProcessAccountDomain, InitiatingProcessAccountName
    | project-rename
    ActorUserId = InitiatingProcessAccountSid, 
    ActorUserAadId = InitiatingProcessAccountObjectId, 
    ActorUserUpn = InitiatingProcessAccountUpn
    // Processes
    | extend
    ActingProcessId = tostring(InitiatingProcessId), 
    ParentProcessId = tostring(InitiatingProcessParentId) 
    | project-away InitiatingProcessId, InitiatingProcessParentId
    | project-rename
    ParentProcessName = InitiatingProcessParentFileName, 
    ParentProcessCreationTime = InitiatingProcessParentCreationTime, 
    ActingProcessName = InitiatingProcessFolderPath, 
    ActingProcessFileName = InitiatingProcessFileName,
    ActingProcessCommandLine = InitiatingProcessCommandLine, 
    ActingProcessMD5 = InitiatingProcessMD5, 
    ActingProcessSHA1 = InitiatingProcessSHA1, //OK
    ActingProcessSHA256 = InitiatingProcessSHA256, 
    ActingProcessIntegrityLevel = InitiatingProcessIntegrityLevel, 
    ActingProcessTokenElevation = InitiatingProcessTokenElevation, 
    ActingProcessCreationTime = InitiatingProcessCreationTime 
    // -- aliases
    | extend 
    Username = ActorUsername,
    UserId = ActorUserId,
    UserIdType = ActorUserIdType,
    User = ActorUsername,
    CommandLine = ActingProcessCommandLine,
    Process = ActingProcessName
    };
    RegistryEvents_M365D
    ```

1. 「実行」 を選択して、KQL が有効であることを確認します。

1. 「保存」を選択し、「関数として保存」を選択します。

1. 「関数として保存」で、以下を設定します。

    |設定|値|
    |---|---|
    |関数名|vimRegEvtM365D|
    |従来のカテゴリ|MyASIM|

1. 「保存」 を選択します。

1. 新しいクエリ タブで、**vimRegEvtM365D** と入力し **実行** を選択します。


### タスク 2: セキュリティ イベント テーブルの KQL 関数を開発します。

このタスクでは、SecurityEvent のワークスペース パーサーである関数を作成します。

1. 新しいクエリ タブを作成します。

1. 新規クエリ2 のスペースに、以下のKQLステートメントを入力します。

    ```KQL
    let RegistryType = datatable (TypeCode: string, TypeName: string) [
    "%%1872", "Reg_None",
    "%%1873", "Reg_Sz",
    "%%1874", "Reg_Expand_Sz",
    "%%1875", "Reg_Binary",
    "%%1876", "Reg_DWord",
    "%%1879", "Reg_Multi_Sz",
    "%%1883", "Reg_QWord"
    ];
    let RegistryAction = datatable (EventOriginalSubType: string, EventType: string) [
        "%%1904", "RegistryValueSet",
        "%%1905", "RegistryValueSet",      
        "%%1906", "RegistryValueDeleted"             
    ];
    let Hives = datatable (KeyPrefix: string, Hive: string) [
        "MACHINE", "HKEY_LOCAL_MACHINE",
        "USER", "HKEY_USERS",   
    ];
    let RegistryEvents=() {
        SecurityEvent
        // -- Filter
        | where EventID == 4657          
        // Event
        | extend
            EventCount = int(1), 
            EventVendor = 'Microsoft', 
            EventProduct = 'Security Events', 
            EventSchemaVersion = '0.1.0', 
            EventStartTime = todatetime(TimeGenerated), 
            EventEndTime = todatetime(TimeGenerated),
            EventOriginalType = tostring(EventID) 
        | project-rename
            EventOriginalSubType = OperationType,
            EventOriginalUid = EventOriginId
        | lookup RegistryAction on EventOriginalSubType
        // Registry
        // Normalize key hive
        | parse ObjectName with "\\REGISTRY\\" KeyPrefix "\\" Key
        | lookup Hives on KeyPrefix
        | extend RegistryKey = strcat (Hive, "\\", Key)
        | project-away Hive, Key, KeyPrefix, ObjectName
        | project-rename
            RegistryValue = ObjectValueName
        | extend
            RegistryValueData = iff (EventOriginalSubType == "%%1906", OldValue, NewValue), 
            RegistryKeyModified = iff (EventOriginalSubType == "%%1905", RegistryKey, ""),
            RegistryValueModified = iff (EventOriginalSubType == "%%1905", RegistryValue, ""),
            RegistryValueDataModified = iff (EventOriginalSubType == "%%1905", OldValue, "")
        | lookup RegistryType on $left.NewValueType == $right.TypeCode
        | project-rename RegistryValueType = TypeName
        | lookup RegistryType on $left.OldValueType == $right.TypeCode
        | project-rename RegistryValueTypeModified = TypeName
        | project-away OldValue, NewValue, OldValueType, NewValueType
        // Device
        | extend
            DvcId = SourceComputerId,
            DvcHostname = Computer,
            DvcOs = 'Windows'
        // User
        | project-rename
            ActorUserId = SubjectUserSid, 
            ActorSessionId = SubjectLogonId, 
            ActorDomainName = SubjectDomainName
        | extend
            ActorUserIdType = 'SID',
            ActorUsername = iff (ActorDomainName == '-', SubjectUserName, SubjectAccount), 
            ActorUsernameType = iff(ActorDomainName == '-', 'Simple', 'Windows'),
            ActingProcessId = tostring(toint(ProcessId)) 
        // Process 
        | project-rename
            ActingProcessName = ProcessName
        // -- Aliases
        | extend
            User = ActorUsername,
            UserId = ActorUserId,
            Dvc = DvcHostname,
            Process = ActingProcessName
        // -- Remove potentially confusing
        | project-away 
            SubjectUserName,
            SubjectAccount
    };
    RegistryEvents
    ```

1. 「実行」 を選択して、KQL が有効であることを確認します。

1. 「保存」を選択し、「関数として保存」を選択します。

1. 「関数として保存」で、以下を設定します。

    |設定|値|
    |---|---|
    |関数名|vimRegEvtSecurityEvent|
    |従来のカテゴリ|MyASIM|

1. 「保存」 を選択します。

1. 新しいクエリ タブで、**vimRegEvtSecurityEvent** と入力し **実行** を選択します。


### タスク 3: 統合ワークスペース パーサーを作成します。

このタスクでは、前の 2 つの関数を組み合わせた統合パーサー関数を作成します。

1. 新しいクエリ タブを作成します。

1. 新しいクエリタブに、以下のKQLステートメントを入力します。

    ```KQL
    union isfuzzy=true
    vimRegEvtM365D,
    vimRegEvtSecurityEvent
    ```

1. 「実行」 を選択して、KQL が有効であることを確認します。

1. 「保存」を選択し、「関数として保存」を選択します。

1. 「関数として保存」で、以下を設定します。

    |設定|値|
    |---|---|
    |関数名|imRegEvt|
    |従来のカテゴリ|MyASIM|

1. 「保存」 を選択します。

1. 新しいクエリ タブで、**imRegEvt** と入力し **実行** を選択します。

1. クエリを次のように更新し、「実行」 を選択します。

    ```KQL
    imRegEvt
    | where ActionType == 'RegistryValueSet'
    ```
    
--!>
