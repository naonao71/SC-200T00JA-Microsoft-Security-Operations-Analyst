# モジュール 6 - ラボ 1 - 演習 3 - データ コネクタを使用して Linux ホストを Microsoft Sentinel に接続する

## ラボ シナリオ

![Lab overview.](../Media/SC-200-Lab_Diagrams_Mod6_L1_Ex3.png)

あなたは、Microsoft Sentinelを導入した企業に勤務するセキュリティ・オペレーション・アナリストです。あなたは、組織内の多くのデータソースからログデータを接続する方法を学ぶ必要があります。次のデータソースは、Common Event Formatting (CEF)とSyslogコネクタを使用するLinux仮想マシンです。

>**ノート:** **[interactive lab simulation](https://mslabs.cloudguides.com/guides/SC-200%20Lab%20Simulation%20-%20Connect%20Linux%20hosts%20to%20Microsoft%20Sentinel%20using%20data%20connectors)** このラボを自分のペースで確認できます。ホスト型のラボと多少の違いはありますが、主要な概念とアイデアは同じです。

### タスク 1: Microsoft Sentinel ワークスペースにアクセスする。

このタスクでは、Microsoft Sentinel ワークスペースにアクセスします。

1. 管理者として WIN1 仮想マシンにログインします。パスワードは**Pa55w.rd** です。  

2. 新しい Microsoft Edge ブラウザーを起動します。

3. Microsoft Edge ブラウザーで Azure portal (https://portal.azure.com) に移動します。

4. **サインイン** ダイアログ ボックスで、ラボ ホスティング プロバイダーから提供された**テナントの電子メール**アカウントをコピーして貼り付け、「**次へ**」を選択します。

5. **パスワードの入力**ダイアログ ボックスで、ラボ ホスティング プロバイダーから提供された**テナントパスワード** をコピーして貼り付け、「**サインイン**」を選択します。

6. Azure portal の検索バーに「*Sentinel*」と入力してから、「**Microsoft Sentinel**」を選択します。

7. Microsoft Sentinel ワークスペースを選択します。

### タスク 2: Common Event Format のコネクタを使用してLinuxホストを接続します。

このタスクでは、LinuxホストをCommon Event Format（CEF）コネクタを使用して Microsoft Sentinelに接続します。

1. 「コンテンツハブ」で、検索ウインドウに「Common Event Format」を入力し、「Common Event Format」を選択します。
2. コネクタ情報ブレードで「インストール」を選択します。
3. コネクタ情報ブレードで「管理」を選択します。
4. 「**Common Event Format（CEF）**」コネクタを選択します。

5. コネクタ情報ブレードで「**コネクタページを開く**」を選択します。

6. 「**1.2 Linux マシンへの CEF コレクターのインストール**」に示されているコマンドをクリップボードにコピーします。

7. LIN1 仮想マシンを起動し、ラボのホスティング業者から提供されたユーザー名とパスワードを使用してログインします。LIN1 サーバー IP アドレスを書き留めます。例として次のスクリーンショットをご覧ください。

   ![Linux ログイン](../Media/LinuxLoginExample.png)

8. WIN1 仮想マシンに戻り、スタート メニュー アイコンを右クリックして、管理者として、Windows PowerShell を起動し、「**Windows PowerShell (管理者)**」を選択します。「**はい**」を選択して、表示されるユーザー アカウント制御ウィンドウで、アプリの実行を許可します。

9. 次の PowerShell コマンドを入力し、特定の Linux サーバー情報に合わせて調整し、Enter キーを押します。

```PowerShell
ssh <insert your linux IP address here> -l <insert linux user name here>
```

7. 「**yes**」と入力して、接続を確認してから、ユーザーのパスワードを入力して、Enter キーを押します。画面は次のようになります。

   ![Linux ログイン](../Media/PSconnectLinux.png)

8. これで、前の手順の「**1.2 Linux マシンへの CEF コレクターのインストール**」に貼り付ける準備ができました。Azure のスクリプトがクリップボードにあることを確認してください。PowerShell で、トップ バーを右クリックし、「**編集**」、「**貼り付け**」の順に選択します。貼り付けたら、次に示すように **python** という単語に **3** を追加します。

   ![ConnectorScript](../Media/ConnectorScript.png)

9. スクリプトを貼り付けて調整したら、Enter キーを押します。スクリプトは Linux サーバーに対してリモートで実行されます。スクリプトが適切に処理されると、次の画面のようになります。

   ![ConnectorScript](../Media/LinuxConnected.png)

### タスク 3: Syslog コネクタを使用して Linux ホストを接続する。

このタスクでは、Linux ホストを Syslog コネクタを使用して Microsoft Sentinel に接続します。

1. WIN1 に接続します。WIN1 は、ワークスペースの Microsoft Sentinel ポータルに既に存在しているはずです。  

2. 「コンテンツハブ」で、検索ウインドウに「Syslog」を入力し、「Syslog」を選択します。
3. コネクタ情報ブレードで「インストール」を選択します。
4. コネクタ情報ブレードで「管理」を選択します。
5. 「**Syslog**」コネクタを選択します。

6. コネクタ情報ブレードで「**コネクタページを開く**」を選択します。

7. **Install agent on a non-Azure Linux Machine**セクションを開きます。

8. **Azure 以外の Linux マシンのエージェントをダウンロードしてインストールする** リンクを選択します。 

9. 「**Linuxサーバー**」のタブを選択します。

10. **Log Analyticsエージェントの手順** を展開して **Linux 用エージェントをダウンロードおよびオンボードする** 領域のコマンドをクリップボードにコピーします。

11. LIN2 仮想マシンを起動し、ラボのホスティング業者から提供されたユーザー名とパスワードを使用してログインします。LIN2 サーバー IP アドレスを書き留めます。例として次のスクリーンショットをご覧ください。

   ![Linux ログイン](../Media/LinuxLoginExample.png)

11. WIN1 仮想マシンに戻り、スタート メニュー アイコンを右クリックして、管理者として、新しい Windows PowerShell を起動し、「**Windows PowerShell (管理者)**」を選択します。「**はい**」を選択して、表示されるユーザー アカウント制御ウィンドウで、アプリの実行を許可します。

**注:** 「**exit**」と入力して、LIN1 に対する接続を閉じて、最後のタスクの**インストールを完了した**場合、Windows PowerShell ウィンドを再使用できます。

10. 次の PowerShell コマンドを入力し、特定の Linux サーバー情報に合わせて調整し、Enter キーを押します。

```PowerShell
ssh <insert your linux IP address here> -l <insert linux user name here>
```

11. 「**yes**」と入力して、接続を確認してから、ユーザーのパスワードを入力して、Enter キーを押します。画面は次のようになります。

   ![Linux ログイン](../Media/PSconnectLinux.png)

12. これで、前の手順の「**Linux 用のダウンロードおよびオンボード エージェント**」に貼り付ける準備ができました。Azure のスクリプトがクリップボードにあることを確認してください。PowerShell で、トップ バーを右クリックし、「**編集**」、「**貼り付け**」の順に選択します。

13. スクリプトが貼り付けられたら、Enter キーを押します。スクリプトは Linux サーバーに対してリモートで実行されます。タスクが完了しました。このコースのこれ以上のラボは、この接続に依存していません。

### タスク 4: 収集するファシリティとその重大度をSyslogコネクタ用に設定します。

このタスクでは、Syslog収集機能を構成します。

1. WIN1仮想マシンに接続します。

2. Microsoft Sentinelポータルで、設定ブレードから「**設定**」、「**ワークスペース設定**」の順に選択します。

3. 「**クラシック**」領域で「**レガシーエージェントの管理**」を選択します。

4. 「**Syslog**」タブを選択します。

5. 「**+ ファシリティの追加**」ボタンを選択します。

6. 「**ファシリティ名**」ドロップダウン メニューから「**auth**」を選択します。

7. 「**+ ファシリティの追加**」ボタンを再度選択します。

8. 「**ファシリティ名**」ドロップダウン メニューから「**authpriv**」を選択します。

9. 「**適用**」を選択します。  このタスクが完了しました。

