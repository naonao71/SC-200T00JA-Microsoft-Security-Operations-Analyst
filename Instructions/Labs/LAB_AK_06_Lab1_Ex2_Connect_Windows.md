﻿# モジュール 6 - ラボ 1 - 演習 2 - データコネクタを使用して Windows デバイスを Azure Sentinel に接続する

### タスク 1: Azure で Windows 仮想マシンを作成する

このタスクでは、 Windows 仮想マシン を作成します。

1. 管理者として WIN1 仮想マシンにログインします。パスワードは **Pa55w.rd** です。  

2. Microsoft Edge ブラウザーで Azure ポータルに移動します https://portal.azure.com

3. **サインイン**ダイアログボックスで、ラボ ホスティング プロバイダーから提供された**テナントの電子メール**アカウントをコピーして貼り付け、「**次へ**」 を選択します。

4. **パスワードの入力**ダイアログ ボックスで、ラボ ホスティング プロバイダーから提供された**テナントパスワード** をコピーして貼り付け、「**サインイン**」を選択します。

5. 「**リソースの作成**」を選択します。

6. **マーケットプレイス**ボックスの検索で、「*Windows10*」 と入力します。 

7. Microsoft Windows10 の**作成**ドロップダウンを選択します。  次に、「**Windows 10Enterprise バージョン 20H2**」 を選択します。

8. サブスクリプションを選択します。

9. まだ作成していない場合は、**rg-AZWIN01** という名前の新しいリソースグループを作成します。

**注:** これは新しいリソースグループである必要があります。  演習後に仮想マシンを削除します。  

10. 仮想マシン名を AZWIN01 に設定します。

11. 適した領域に設定してください。  適切な地域が既定になる場合があります。

12. Azure で使用できるユーザー名を選択して入力します。

13. 任意のパスワードを入力します。 

**ヒント:** テナントパスワードを使用するのが最も簡単な方法です。

14. ライセンス確認を選択します。 を選択して確認します。

15. 「**レビュー + 作成**」 を選択します。

16. 「**作成**」を選択します。リソースが作成されるのを待ちますこれには数分かかることがあります。

### タスク 2: Azure Windows VM の接続

このタスクでは、Azure Windows 仮想マシンを Azure Sentinel に接続します。

1. Azure ポータルの検索バーに 「*Sentinel*」 と入力し、「**Azure Sentinel**」 を選択します。

2. 先ほど作成した Azure Sentinel ワークスペースを選択します。

3. データ コネクタ タブで、リストから「**セキュリティ イベント**」コネクタを選択します。

4. プロンプトが表示されたら、Azure Sentinel ワークスペースを選択します。

5. コネクタ情報ブレードで「**コネクタページを開く**」を選択します。

**注:** Windows 仮想マシンへのエージェントのインストールと非 Azure　Windows マシンへのエージェントのインストールの手順が逆になる場合があります。  リンクは、テキストが逆になっている場合でも、適切な場所に移動します。

6. 「**Windows 仮想マシンにエージェントをインストールする**」プションを選択します。

7. 「**Azure Linux 仮想マシンのエージェントのダウンロードとインストール**」を選択します。

8. 前の手順で作成したリストから **AZWIN01** 仮想マシンを選択し、「**接続**」を選択します。接続メッセージが消えるまで待ちます。

9. ナビゲーションリストで「**仮想マシン**」を選択しますこれで、マシンが接続されていることがわかると思います。

**注:** 仮想マシンは、このタスクでのみ使用されます。  

10. Azure ポータル検索で、「*リソースグループ*」を入力します。  「**リソース グループ**」を選択します。

11. 一覧から 「**rg-AZWIN01**」 を選択します。

12. コマンドバーから「**リソース グループの削除**」を選択します。

13. 「削除してもよろしいですか]ペインに 「**rg-AZWIN01**」 と入力し、「**削除**」を選択します。

### タスク 3: 非 Azure Windows 機械の接続

このタスクでは、非 Azure Windows 仮想マシンを AzureSentinel に接続します。

1. 管理者として WIN2 仮想マシンにログインします。パスワードは **Pa55w.rd** です。  

2. ブラウザを開き、新しい Microsoft Edge ブラウザーを検索、ダウンロード、およびインストールします。新しい Microsoft Edge ブラウザーを起動します。

3. ブラウザーを開き、資格情報を使用して https://portal.azure.com の Azure ポータルにログインします。

4. Azure ポータルの検索バーに 「*Sentinel*」 と入力し、「**Azure Sentinel**」 を選択します。

5. Azure Sentinel ワークスペースを選択します。

6. データ コネクタ タブで、リストから「**セキュリティ イベント**」コネクタを選択します。

7. コネクタ情報ブレードで「**コ ネクタページを開く**」を選択します。

8. ストリーミングするイベントの選択領域で、「**すべてのイベント**」を選択し、「**変更の適用**」を選択します。

9. 「**非 Azure Windows 仮想マシンにインストールエージェント**」を選択します。

**注:** Windows 仮想マシンへのエージェントのインストールと非 Azure　Windows マシンへのエージェントのインストールの手順が逆になる場合があります。リンクは、テキストが逆になっている場合でも、適切な場所に移動します。

10. 「**非 Azure Windows 仮想マシンのエージェントのダウンロードとインストール**」を選択します。 

11. **Windows エージェントのダウンロード （64 ビット）** のリンクを選択します。

12. ダウンロードした .exe ファイルを実行し、確認と表示される可能性のあるユーザーアカウント制御プロンプトを実行します。

13. ウェルカムダイアログで「**次へ**」を選択します。

14. マイクロソフトソフトウェアライセンス条項ページで「**同意する**」を選択します。  宛先プロンプトで、「**次へ**」を選択します。

15. エージェントのセットアップ オプションプロンプトで、「**エージェントを Azure Log Analytics （OMS）**」 に接続するオプションを選択し、「**次へ**」を選択します。

16. ブラウザで、エージェントの管理ページから**ワークスペース ID** をコピーし、ダイアログのワークスペース ID に貼り付けます。 

17. ブラウザで、エージェントの管理ページから主キーをコピーし、ダイアログの**主キー**に貼り付けます。 

18. 「**次へ**」を選択します。

19. Microsoft Update ページで「**次へ**」を選択します。

20. 次に、「**インストール**」を選択します。

### タスク 4: Sysmon ログをインストールして収集します。

このタスクでは、Sysmon ログをインストールして収集します。

引き続き WIN2 仮想マシンに接続する必要があります。  次の手順では、既定構成で Sysmon をインストールします。.  実稼働マシンで使用する Sysmon のコミュニティベースの構成を調査する必要があります

1. ブラウザーで、次のログイン URL に移動します。https://docs.microsoft.com/sysinternals/downloads/sysmon

2. **Sysmon のダウンロード**を選択して、ページから Sysmon をダウンロードします。

3. ダウンロードしたファイルを開き、ファイルを新しいディレクトリ c:\sysmon に抽出します。

4. Windows の WIN2 タスクバーの検索ボックスに*コマンド*を入力します。  検索結果には、コマンドプロンプトアプリが表示されます。  コマンドプロンプトアプリを右クリックし、**管理者として実行**を選択します。  表示されるユーザーアカウント制御のプロンプトを確認します。

5. *cd \sysmon* と入力する。

6. type *notepad sysmon.xml* と入力して、新しいファイルを作成します。

7. Open a tab in the browser and navigate to: https://github.com/SwiftOnSecurity/sysmon-config/blob/master/sysmonconfig-export.xml

8. そのファイルの内容を Github から作成した sysmon.xml メモ帳ファイルにコピーしてファイルを保存します。

9. コマンドプロンプトで次のように入力し、Enterキーを押します。
    sysmon.exe -accepteula -i sysmon.xml

10. ブラウザで、https://portal.azure.com のAzureポータルに移動します 

11. Azure ポータルの検索バーに 「*Sentinel*」 と入力し、「**Azure Sentinel**」 を選択します。

12. Azure Sentinel で、構成領域から「**設定**」を選択し、「**ワークスペース設定**」タブを選択します

13. Azure Sentinel ワークスペースが選択されていることを確認してください。

14. 設定で「**エージェントの構成**」を選択します

15. 「**Windows イベントログ**」タブを選択します。

16. 「**Windows イベントログの追加**」ボタンを選択します。

17. ログ名フィールドに 「**Microsoft-Windows-Sysmon/Operational**」 と入力します。

18. 「**適用**」を選択します。

### タスク 5: Microsoft Defender for Endpoint ディバイスをオンボードする。

このタスクでは、デバイスを Microsoft Defender for Endpoint にオンボードします。

**注:** このコースの最初のモジュールでラボを完了した場合は、すでにこのタスクを実行しています。  そのラボ演習で同じ仮想マシンを使用している場合は、このタスクを実行する必要はありません。

1. 管理者として WIN1 仮想マシンにログインします。パスワードは **Pa55w.rd** です。  

2. https://securitycenter.microsoft.com で Microsoft Defender セキュリティ センターに進みます。現在ポータルを使用していない場合は、**テナン電子メール**の資格情報を使用してログインします。

3. 左側のメニュー バーで **「設定」** を選択します。

4. デバイス管理セクションで **「オンボーディング」** を選択します。

5. 「**パッケージのダウンロード**」を選択します。

6. ダウンロードした .zip ファイルを解凍します。

7. **管理者**として Windows コマンドプロンプトを実行し、表示されるユーザーアカウント制御プロンプトに同意します。

8. 管理者として抽出したばかりの WindowsDefenderATPLocalOnboardingScript.cmd ファイルを実行します。**注** 既定では、ファイルは c:\ users \ admin \ downloads ディレクトリにあります。スクリプトの質問に対して 「Y」 と回答します。 

9. Microsoft Defender Security Center ポータルのオンボーディングページから、検出テストスクリプトをコピーし、開いている**管理者：** で実行します。**コマンドプロンプト**ウィンドウ。

10.  Microsoft Defender Security Center ポータルメニューで、左側のナビゲーションから**デバイスインベントリ**アイコンを選択します。お使いになっているデバイスがリストに表示されます。**注** デバイスがポータルに表示されるまでに最高 5 分かかることがあります。

## 演習 3 に進みます。